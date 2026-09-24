package sender

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"xport/internal/monitor"
	"xport/internal/tlsutil"
	"xport/internal/wire"
)

type ClientPool struct {
	watchDir          string
	targetAddr        string
	certFile          string
	keyFile           string
	allowedReceiverFP []string
	parallel          int
	afterAction       string // "archive" or "delete"
	queue             *Queue
	scanner           *Scanner
	tracker           *monitor.Tracker

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewClientPool(
	watchDir string,
	targetAddr string,
	certFile string,
	keyFile string,
	allowedReceiverFP []string,
	parallel int,
	afterAction string,
	queue *Queue,
	scanner *Scanner,
	tracker *monitor.Tracker,
) *ClientPool {
	if parallel <= 0 {
		parallel = 1
	}
	if afterAction == "" {
		afterAction = "archive"
	}

	return &ClientPool{
		watchDir:          watchDir,
		targetAddr:        targetAddr,
		certFile:          certFile,
		keyFile:           keyFile,
		allowedReceiverFP: allowedReceiverFP,
		parallel:          parallel,
		afterAction:       afterAction,
		queue:             queue,
		scanner:           scanner,
		tracker:           tracker,
		stopCh:            make(chan struct{}),
	}
}

func (p *ClientPool) Start(ctx context.Context) {
	for i := 0; i < p.parallel; i++ {
		p.wg.Add(1)
		go p.workerLoop(ctx, i+1)
	}
}

func (p *ClientPool) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.queue.Stop()
		p.wg.Wait()
	})
}

// dialPersistent creates a new TLS 1.3 connection to the receiver enforcing a 10s handshake deadline.
func (p *ClientPool) dialPersistent() (net.Conn, error) {
	tlsCfg, err := tlsutil.NewClientTLSConfig(p.certFile, p.keyFile, p.allowedReceiverFP)
	if err != nil {
		return nil, fmt.Errorf("client tls config error: %w", err)
	}

	dialer := &net.Dialer{Timeout: wire.HandshakeTimeout}
	rawConn, err := dialer.Dial("tcp", p.targetAddr)
	if err != nil {
		return nil, fmt.Errorf("dial failed to %s: %w", p.targetAddr, err)
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(wire.HandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}

	return tlsConn, nil
}

// workerLoop processes files sequentially, keeping the TLS connection persistent across files.
func (p *ClientPool) workerLoop(ctx context.Context, workerID int) {
	defer p.wg.Done()

	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	dialBackoff := 1 * time.Second
	const maxDialBackoff = 30 * time.Second

	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		item, ok := p.queue.Pop()
		if !ok {
			// Queue stopped
			return
		}

		// Ensure persistent connection is active
		if conn == nil {
			var err error
			conn, err = p.dialPersistent()
			if err != nil {
				log.Printf("[sender-%d] connect error to %s: %v (retrying in %v)", workerID, p.targetAddr, err, dialBackoff)
				if p.tracker != nil {
					p.tracker.RecordError()
				}
				p.queue.Requeue(item)
				select {
				case <-p.stopCh:
					return
				case <-time.After(dialBackoff):
				}
				dialBackoff *= 2
				if dialBackoff > maxDialBackoff {
					dialBackoff = maxDialBackoff
				}
				continue
			}
			dialBackoff = 1 * time.Second
		}

		// Transfer file
		err := p.transferFile(conn, item)
		if err != nil {
			log.Printf("[sender-%d] transfer failed for %s: %v", workerID, item.Filename, err)
			_ = conn.Close()
			conn = nil // Reset connection to re-dial on next attempt

			if p.tracker != nil {
				p.tracker.RecordError()
			}
			quarantined := p.queue.RecordFailure(item, err)
			if quarantined && p.scanner != nil {
				p.scanner.MarkCompleted(item.Filename)
			}
			// Backoff on transfer failure to prevent tight CPU spin
			select {
			case <-p.stopCh:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		// Transfer succeeded: post-commit action
		if postCommitErr := p.postCommit(item); postCommitErr != nil {
			log.Printf("[sender-%d] CRITICAL: post-commit error for %s: %v; preserving file tracking to avoid infinite retransmission", workerID, item.Filename, postCommitErr)
			if p.tracker != nil {
				p.tracker.RecordError()
			}
		} else {
			p.queue.RecordSuccess(item.Filename)
			if p.scanner != nil {
				p.scanner.MarkCompleted(item.Filename)
			}
			if p.tracker != nil {
				p.tracker.RecordSuccess(uint64(item.Size))
			}
		}
	}
}

func (p *ClientPool) transferFile(conn net.Conn, item FileItem) error {
	f, err := os.Open(item.Path)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}
	payloadSize := uint64(info.Size())

	// Wrap connection with 60s read/write stall deadline
	deadlineConn := wire.NewDeadlineConn(conn, wire.ReadWriteTimeout)

	// Write request header
	if err := wire.WriteRequestHeader(deadlineConn, item.Filename, payloadSize); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Stream payload using 1 MB buffer and append SHA-256 trailer
	if _, err := wire.SendStream(deadlineConn, f, payloadSize); err != nil {
		return fmt.Errorf("failed to stream payload: %w", err)
	}

	// Read receiver response (ACK 0x00 or NACK 0x01)
	if err := wire.ReadResponse(deadlineConn); err != nil {
		return fmt.Errorf("receiver response error: %w", err)
	}

	return nil
}

func (p *ClientPool) postCommit(item FileItem) error {
	switch p.afterAction {
	case "delete":
		return os.Remove(item.Path)
	case "archive":
		fallthrough
	default:
		sentDir := filepath.Join(p.watchDir, ".sent")
		if err := os.MkdirAll(sentDir, 0755); err != nil {
			return fmt.Errorf("failed to create .sent dir: %w", err)
		}
		destPath := filepath.Join(sentDir, item.Filename)
		if _, err := os.Stat(destPath); err == nil {
			// Avoid collision by appending timestamp
			destPath = filepath.Join(sentDir, fmt.Sprintf("%s.%d", item.Filename, time.Now().UnixNano()))
		}
		return os.Rename(item.Path, destPath)
	}
}
