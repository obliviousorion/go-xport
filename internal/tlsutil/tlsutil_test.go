package tlsutil

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertGenerationAndPinning(t *testing.T) {
	tempDir := t.TempDir()

	// Generate Server Cert
	serverCertPath := filepath.Join(tempDir, "server.crt")
	serverKeyPath := filepath.Join(tempDir, "server.key")
	serverFP, err := GenerateCert("server", 365, serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("GenerateCert for server failed: %v", err)
	}

	loadedServerFP, err := LoadCertFingerprint(serverCertPath)
	if err != nil {
		t.Fatalf("LoadCertFingerprint failed: %v", err)
	}
	if loadedServerFP != serverFP {
		t.Fatalf("fingerprint mismatch: %s vs %s", serverFP, loadedServerFP)
	}

	// Generate Client Cert
	clientCertPath := filepath.Join(tempDir, "client.crt")
	clientKeyPath := filepath.Join(tempDir, "client.key")
	clientFP, err := GenerateCert("client", 365, clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("GenerateCert for client failed: %v", err)
	}

	// Generate Rogue Cert
	rogueCertPath := filepath.Join(tempDir, "rogue.crt")
	rogueKeyPath := filepath.Join(tempDir, "rogue.key")
	_, err = GenerateCert("rogue", 365, rogueCertPath, rogueKeyPath)
	if err != nil {
		t.Fatalf("GenerateCert for rogue failed: %v", err)
	}

	// Test 1: Successful mutual TLS handshake with pinned fingerprints
	serverTLS, err := NewServerTLSConfig(serverCertPath, serverKeyPath, []string{clientFP})
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, err = conn.Read(buf)
		errCh <- err
	}()

	clientTLS, err := NewClientTLSConfig(clientCertPath, clientKeyPath, []string{serverFP})
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	cConn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, clientTLS)
	if err != nil {
		t.Fatalf("client failed to dial server with valid cert: %v", err)
	}
	_, _ = cConn.Write([]byte("ping"))
	_ = cConn.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("server encountered error during handshake: %v", err)
	}

	// Test 2: Rogue client with unpinned cert rejected by server
	rogueClientTLS, err := NewClientTLSConfig(rogueCertPath, rogueKeyPath, []string{serverFP})
	if err != nil {
		t.Fatalf("NewClientTLSConfig for rogue failed: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	rogueConn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, rogueClientTLS)
	if err == nil {
		// Try to read/write to trigger handshake error if delayed
		_, err = rogueConn.Write([]byte("ping"))
		if err == nil {
			buf := make([]byte, 1)
			_ = rogueConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err = rogueConn.Read(buf)
		}
		_ = rogueConn.Close()
		if err == nil {
			t.Fatal("expected rogue client connection to be rejected by server, but it succeeded")
		}
	}

	// Ensure files exist on disk
	for _, p := range []string{serverCertPath, serverKeyPath, clientCertPath, clientKeyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file %s was not created: %v", p, err)
		}
	}
}

func TestGenerateCertCreatesDirectories(t *testing.T) {
	tempDir := t.TempDir()
	nestedCertPath := filepath.Join(tempDir, "deep", "nested", "keys", "node.crt")
	nestedKeyPath := filepath.Join(tempDir, "deep", "nested", "keys", "node.key")

	fp, err := GenerateCert("node", 365, nestedCertPath, nestedKeyPath)
	if err != nil {
		t.Fatalf("GenerateCert failed to create nested directories: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("invalid fingerprint length: %d", len(fp))
	}
	if _, err := os.Stat(nestedCertPath); err != nil {
		t.Fatalf("nested cert was not created: %v", err)
	}
}
