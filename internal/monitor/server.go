package monitor

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"xport/internal/tlsutil"
)

// Server serves health and diagnostic endpoints: /status, /healthz, and /metrics.
type Server struct {
	tracker      *Tracker
	bindAddr     string
	certFile     string
	keyFile      string
	statusPeerFP string
	httpServer   *http.Server
	listener     net.Listener
}

func NewServer(tracker *Tracker, bindAddr, certFile, keyFile, statusPeerFP string) (*Server, error) {
	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		host = bindAddr
	}

	isLoopback := host == "127.0.0.1" || host == "localhost" || host == "::1"

	// Enforcement from specification:
	// "When configured with a non-loopback IP, the daemon requires -status-peer-fp <MONITOR_FP>.
	//  It wraps the status listener in TLS 1.3 using the node's local link certificate and requires
	//  mutual certificate verification against the monitor's pinned fingerprint.
	//  It must fail to boot if bound to an external IP without a status peer fingerprint."
	if !isLoopback && statusPeerFP == "" {
		return nil, errors.New("security error: binding status listener to non-loopback address requires -status-peer-fp")
	}

	s := &Server{
		tracker:      tracker,
		bindAddr:     bindAddr,
		certFile:     certFile,
		keyFile:      keyFile,
		statusPeerFP: statusPeerFP,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.httpServer = &http.Server{
		Addr:         bindAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return s, nil
}

func (s *Server) Start() error {
	host, _, err := net.SplitHostPort(s.bindAddr)
	if err != nil {
		host = s.bindAddr
	}
	isLoopback := host == "127.0.0.1" || host == "localhost" || host == "::1"

	if isLoopback || s.statusPeerFP == "" {
		ln, err := net.Listen("tcp", s.bindAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on status addr %s: %w", s.bindAddr, err)
		}
		s.listener = ln
	} else {
		// Non-loopback: wrap in mutual TLS 1.3
		tlsCfg, err := tlsutil.NewServerTLSConfig(s.certFile, s.keyFile, []string{s.statusPeerFP})
		if err != nil {
			return fmt.Errorf("failed to configure TLS for status server: %w", err)
		}
		ln, err := tls.Listen("tcp", s.bindAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to tls.Listen on status addr %s: %w", s.bindAddr, err)
		}
		s.listener = ln
	}

	go func() {
		_ = s.httpServer.Serve(s.listener)
	}()

	return nil
}

func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.tracker.Evaluate()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.tracker.Evaluate()
	if st.State == StateFail {
		w.WriteHeader(http.StatusServiceUnavailable)
		msg := "Service Unavailable (FAIL)\n"
		if len(st.ActiveIssues) > 0 {
			msg += strings.Join(st.ActiveIssues, "\n") + "\n"
		}
		_, _ = w.Write([]byte(msg))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf("OK (%s)\n", st.State)))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.tracker.Evaluate()

	var stateVal int
	switch st.State {
	case StateOK:
		stateVal = 0
	case StateWarn:
		stateVal = 1
	case StateFail:
		stateVal = 2
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP xport_state Current health state (0=OK, 1=WARN, 2=FAIL)\n")
	fmt.Fprintf(w, "# TYPE xport_state gauge\n")
	fmt.Fprintf(w, "xport_state{node=%q,role=%q} %d\n", st.NodeID, st.Role, stateVal)

	fmt.Fprintf(w, "# HELP xport_files_total Total files processed\n")
	fmt.Fprintf(w, "# TYPE xport_files_total counter\n")
	fmt.Fprintf(w, "xport_files_total{node=%q,role=%q} %d\n", st.NodeID, st.Role, st.FilesTotal)

	fmt.Fprintf(w, "# HELP xport_bytes_total Total bytes processed\n")
	fmt.Fprintf(w, "# TYPE xport_bytes_total counter\n")
	fmt.Fprintf(w, "xport_bytes_total{node=%q,role=%q} %d\n", st.NodeID, st.Role, st.BytesTotal)

	fmt.Fprintf(w, "# HELP xport_pending_files Current queue depth\n")
	fmt.Fprintf(w, "# TYPE xport_pending_files gauge\n")
	fmt.Fprintf(w, "xport_pending_files{node=%q,role=%q} %d\n", st.NodeID, st.Role, st.WaitingFiles)

	fmt.Fprintf(w, "# HELP xport_failed_files Files in failed quarantine\n")
	fmt.Fprintf(w, "# TYPE xport_failed_files gauge\n")
	fmt.Fprintf(w, "xport_failed_files{node=%q,role=%q} %d\n", st.NodeID, st.Role, st.FailedFiles)

	fmt.Fprintf(w, "# HELP xport_disk_free_percent Free disk space percentage\n")
	fmt.Fprintf(w, "# TYPE xport_disk_free_percent gauge\n")
	fmt.Fprintf(w, "xport_disk_free_percent{node=%q,role=%q} %d\n", st.NodeID, st.Role, st.Disk.FreePercent)
}
