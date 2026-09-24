package receiver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xport/internal/monitor"
	"xport/internal/tlsutil"
	"xport/internal/wire"
)

type Server struct {
	incomingDir      string
	listenAddr       string
	certFile         string
	keyFile          string
	allowedSenderFPs []string
	maxSize          uint64
	collisionPolicy  string
	autoExtract      bool
	tracker          *monitor.Tracker
	listener         net.Listener
	activeConnCount  int32
	stopCh           chan struct{}
	wg               sync.WaitGroup

	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

func NewServer(incomingDir, listenAddr, certFile, keyFile string, allowedSenderFPs []string, maxSize uint64, tracker *monitor.Tracker) *Server {
	return &Server{
		incomingDir:      incomingDir,
		listenAddr:       listenAddr,
		certFile:         certFile,
		keyFile:          keyFile,
		allowedSenderFPs: allowedSenderFPs,
		maxSize:          maxSize,
		collisionPolicy:  "rename",
		tracker:          tracker,
		stopCh:           make(chan struct{}),
		conns:            make(map[net.Conn]struct{}),
	}
}

func (s *Server) SetCollisionPolicy(policy string) {
	s.collisionPolicy = policy
}

func (s *Server) SetAutoExtract(autoExtract bool) {
	s.autoExtract = autoExtract
}

func (s *Server) Start() error {
	// Execute boot cleanup on .staging/
	if err := BootCleanup(s.incomingDir); err != nil {
		return fmt.Errorf("boot cleanup error: %w", err)
	}

	tlsCfg, err := tlsutil.NewServerTLSConfig(s.certFile, s.keyFile, s.allowedSenderFPs)
	if err != nil {
		return fmt.Errorf("failed to create server TLS config: %w", err)
	}

	ln, err := tls.Listen("tcp", s.listenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}
	s.listener = ln

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return nil
}

func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	var tempDelay time.Duration

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				log.Printf("[receiver] accept error: %v", err)
				if s.tracker != nil {
					s.tracker.RecordError()
				}
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				select {
				case <-time.After(tempDelay):
				case <-s.stopCh:
					return
				}
				continue
			}
		}
		tempDelay = 0

		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		atomic.AddInt32(&s.activeConnCount, 1)
		if s.tracker != nil {
			s.tracker.SetActiveConnections(int(atomic.LoadInt32(&s.activeConnCount)))
		}

		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				atomic.AddInt32(&s.activeConnCount, -1)
				if s.tracker != nil {
					s.tracker.SetActiveConnections(int(atomic.LoadInt32(&s.activeConnCount)))
				}
				_ = c.Close()
			}()

			s.handleConnection(c)
		}(conn)
	}
}

func (s *Server) handleConnection(c net.Conn) {
	// Enforce 10s handshake deadline
	_ = c.SetDeadline(time.Now().Add(wire.HandshakeTimeout))
	tlsConn, ok := c.(*tls.Conn)
	if ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[receiver] handshake error: %v", err)
			if s.tracker != nil {
				s.tracker.RecordError()
			}
			return
		}
	}

	// Persistent connection loop: receive multiple files over this connection
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		// Enforce 2m receiver idle deadline waiting for the next file header
		_ = c.SetReadDeadline(time.Now().Add(wire.ReceiverIdleTimeout))
		filename, payloadSize, err := wire.ReadRequestHeader(c, s.maxSize)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				// Client cleanly closed connection or idle timeout
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Idle timeout expired
				return
			}

			// Protocol violation or max-size exceeded: send NACK and close connection
			log.Printf("[receiver] header error: %v", err)
			_ = wire.WriteNack(c, sanitizeNackMessage(err, "invalid header"))
			if s.tracker != nil {
				s.tracker.RecordError()
			}
			return
		}

		// File reception started: enforce 60s read/write stall deadline
		deadlineConn := wire.NewDeadlineConn(c, wire.ReadWriteTimeout)

		// Create isolated staging file in <dir>/.staging/<rand-hex>.tmp
		stagedFile, stagedPath, err := CreateStagedFile(s.incomingDir)
		if err != nil {
			log.Printf("[receiver] staging create error: %v", err)
			_ = wire.WriteNack(deadlineConn, sanitizeNackMessage(err, "internal staging error"))
			if s.tracker != nil {
				s.tracker.RecordError()
			}
			return
		}

		// Stream incoming payload directly to staging file using 1MB buffer and verify SHA-256 trailer
		err = wire.ReceiveStream(stagedFile, deadlineConn, payloadSize)
		if err != nil {
			log.Printf("[receiver] streaming error for %s: %v", filename, err)
			_ = stagedFile.Close()
			_ = os.Remove(stagedPath)
			_ = wire.WriteNack(deadlineConn, sanitizeNackMessage(err, "stream failure"))
			if s.tracker != nil {
				s.tracker.RecordError()
			}
			return
		}

		// Execute strict durability barrier:
		// 1. stagedFile.Sync()
		// 2. stagedFile.Close()
		// 3. Atomically place into destination
		// 4. dir.Sync()
		// 5. If autoExtract, extract .tar with expansion limits and fsync
		// 6. Send 0x00 ACK
		_, err = CommitBarrier(stagedFile, stagedPath, s.incomingDir, filename, s.collisionPolicy, s.autoExtract, deadlineConn)
		if err != nil {
			log.Printf("[receiver] commit barrier error for %s: %v", filename, err)
			_ = wire.WriteNack(deadlineConn, sanitizeNackMessage(err, "commit barrier failure"))
			if s.tracker != nil {
				s.tracker.RecordError()
			}
			return
		}

		if s.tracker != nil {
			s.tracker.RecordSuccess(payloadSize)
		}
	}
}

// sanitizeNackMessage strips sensitive local server paths from error strings
// and returns high-level diagnostic reason for the sender.
func sanitizeNackMessage(err error, fallbackCategory string) string {
	if err == nil {
		return fallbackCategory
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "PERM:") {
		return msg
	}
	if strings.Contains(msg, "already exists") {
		return "PERM: collision: file already exists in destination"
	}
	if strings.Contains(msg, "quota exceeded") {
		return "PERM: extraction quota exceeded"
	}
	if strings.Contains(msg, "exceeds maximum allowed size") {
		return "PERM: payload size exceeds maximum allowed size"
	}
	if strings.Contains(msg, "invalid filename") {
		return "PERM: invalid filename"
	}
	if strings.Contains(msg, "sha-256 checksum mismatch") {
		return "stream failure: checksum mismatch"
	}
	if strings.Contains(msg, "unexpected EOF") {
		return "stream failure: short read"
	}
	return fallbackCategory
}
