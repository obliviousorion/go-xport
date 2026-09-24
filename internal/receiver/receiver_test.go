package receiver

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xport/internal/tlsutil"
	"xport/internal/wire"
)

func TestBootCleanup(t *testing.T) {
	tempDir := t.TempDir()
	stagingDir := filepath.Join(tempDir, ".staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		t.Fatalf("failed to create staging dir: %v", err)
	}

	tmpFile1 := filepath.Join(stagingDir, "aborted1.tmp")
	tmpFile2 := filepath.Join(stagingDir, "aborted2.tmp")
	keepFile := filepath.Join(stagingDir, "important.data")

	_ = os.WriteFile(tmpFile1, []byte("garbage"), 0644)
	_ = os.WriteFile(tmpFile2, []byte("garbage"), 0644)
	_ = os.WriteFile(keepFile, []byte("keep"), 0644)

	if err := BootCleanup(tempDir); err != nil {
		t.Fatalf("BootCleanup failed: %v", err)
	}

	if _, err := os.Stat(tmpFile1); !os.IsNotExist(err) {
		t.Errorf("expected tmpFile1 to be deleted")
	}
	if _, err := os.Stat(tmpFile2); !os.IsNotExist(err) {
		t.Errorf("expected tmpFile2 to be deleted")
	}
	if _, err := os.Stat(keepFile); err != nil {
		t.Errorf("expected non-tmp file to be preserved")
	}
}

func TestCommitBarrier(t *testing.T) {
	tempDir := t.TempDir()
	stagedFile, stagedPath, err := CreateStagedFile(tempDir)
	if err != nil {
		t.Fatalf("CreateStagedFile failed: %v", err)
	}

	content := []byte("model checkpoint shard payload")
	if _, err := stagedFile.Write(content); err != nil {
		t.Fatalf("failed to write to staged file: %v", err)
	}

	filename := "checkpoint-001.bin"
	var replyBuf bytes.Buffer

	committedPath, err := CommitBarrier(stagedFile, stagedPath, tempDir, filename, "rename", false, &replyBuf)
	if err != nil {
		t.Fatalf("CommitBarrier failed: %v", err)
	}

	// Verify reply is 0x00 ACK
	if replyBuf.Len() != 1 || replyBuf.Bytes()[0] != wire.AckByte {
		t.Fatalf("expected 0x00 ACK, got: %v", replyBuf.Bytes())
	}

	// Verify file is placed in incoming root
	targetPath := filepath.Join(tempDir, filename)
	if committedPath != targetPath {
		t.Fatalf("expected committed path %s, got %s", targetPath, committedPath)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("committed file does not exist: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("committed file content mismatch")
	}

	// Verify staging file was renamed away
	if _, err := os.Stat(stagedPath); !os.IsNotExist(err) {
		t.Errorf("staging file still exists at %s", stagedPath)
	}
}

func TestCommitBarrierCollision(t *testing.T) {
	tempDir := t.TempDir()
	filename := "existing.bin"
	origPath := filepath.Join(tempDir, filename)
	_ = os.WriteFile(origPath, []byte("original"), 0644)

	// Test 1: reject policy
	stagedFile1, stagedPath1, _ := CreateStagedFile(tempDir)
	_, _ = stagedFile1.Write([]byte("duplicate"))
	var replyBuf1 bytes.Buffer
	_, err := CommitBarrier(stagedFile1, stagedPath1, tempDir, filename, "reject", false, &replyBuf1)
	if err == nil {
		t.Fatalf("expected error on collision with reject policy")
	}

	// Test 2: rename policy
	stagedFile2, stagedPath2, _ := CreateStagedFile(tempDir)
	_, _ = stagedFile2.Write([]byte("renamed-version"))
	var replyBuf2 bytes.Buffer
	_, err = CommitBarrier(stagedFile2, stagedPath2, tempDir, filename, "rename", false, &replyBuf2)
	if err != nil {
		t.Fatalf("unexpected error on collision with rename policy: %v", err)
	}
	// Check that original still exists with original content
	data, _ := os.ReadFile(origPath)
	if string(data) != "original" {
		t.Fatalf("original file was corrupted: %s", string(data))
	}

	// Test 3: overwrite policy
	stagedFile3, stagedPath3, _ := CreateStagedFile(tempDir)
	_, _ = stagedFile3.Write([]byte("overwritten"))
	var replyBuf3 bytes.Buffer
	_, err = CommitBarrier(stagedFile3, stagedPath3, tempDir, filename, "overwrite", false, &replyBuf3)
	if err != nil {
		t.Fatalf("unexpected error on collision with overwrite policy: %v", err)
	}
	data, _ = os.ReadFile(origPath)
	if string(data) != "overwritten" {
		t.Fatalf("expected overwritten content, got: %s", string(data))
	}
}

func TestReceiverServerTransfer(t *testing.T) {
	tempDir := t.TempDir()
	keysDir := filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(keysDir, 0755)

	recvCert := filepath.Join(keysDir, "recv.crt")
	recvKey := filepath.Join(keysDir, "recv.key")
	recvFP, err := tlsutil.GenerateCert("receiver", 365, recvCert, recvKey)
	if err != nil {
		t.Fatalf("failed to generate receiver cert: %v", err)
	}

	sendCert := filepath.Join(keysDir, "send.crt")
	sendKey := filepath.Join(keysDir, "send.key")
	sendFP, err := tlsutil.GenerateCert("sender", 365, sendCert, sendKey)
	if err != nil {
		t.Fatalf("failed to generate sender cert: %v", err)
	}

	incomingDir := filepath.Join(tempDir, "incoming")
	_ = os.MkdirAll(incomingDir, 0755)

	server := NewServer(incomingDir, "127.0.0.1:0", recvCert, recvKey, []string{sendFP}, 1024*1024*10, nil)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	serverAddr := server.Addr().String()

	// Connect client
	clientTLS, err := tlsutil.NewClientTLSConfig(sendCert, sendKey, []string{recvFP})
	if err != nil {
		t.Fatalf("client TLS config failed: %v", err)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, clientTLS)
	if err != nil {
		t.Fatalf("client failed to dial server: %v", err)
	}
	defer conn.Close()

	// Send file 1
	filename := "shard-001.bin"
	payload := []byte("high-speed tensor data stream")
	if err := wire.WriteRequestHeader(conn, filename, uint64(len(payload))); err != nil {
		t.Fatalf("WriteRequestHeader failed: %v", err)
	}
	if _, err := wire.SendStream(conn, bytes.NewReader(payload), uint64(len(payload))); err != nil {
		t.Fatalf("SendStream failed: %v", err)
	}
	if err := wire.ReadResponse(conn); err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}

	// Verify file received
	committedPath := filepath.Join(incomingDir, filename)
	data, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("file not committed: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("committed payload mismatch")
	}

	// Send file 2 on the SAME persistent connection
	filename2 := "shard-002.bin"
	payload2 := []byte("second tensor shard over persistent TLS connection")
	if err := wire.WriteRequestHeader(conn, filename2, uint64(len(payload2))); err != nil {
		t.Fatalf("WriteRequestHeader 2 failed: %v", err)
	}
	if _, err := wire.SendStream(conn, bytes.NewReader(payload2), uint64(len(payload2))); err != nil {
		t.Fatalf("SendStream 2 failed: %v", err)
	}
	if err := wire.ReadResponse(conn); err != nil {
		t.Fatalf("ReadResponse 2 failed: %v", err)
	}

	committedPath2 := filepath.Join(incomingDir, filename2)
	data2, err := os.ReadFile(committedPath2)
	if err != nil {
		t.Fatalf("file 2 not committed: %v", err)
	}
	if !bytes.Equal(data2, payload2) {
		t.Fatalf("committed payload 2 mismatch")
	}
}

func TestExtractTar(t *testing.T) {
	tempDir := t.TempDir()
	tarFile := filepath.Join(tempDir, "archive.tar")
	destDir := filepath.Join(tempDir, "extracted")

	// Create test tar archive with normal and malicious path traversal entries
	f, err := os.Create(tarFile)
	if err != nil {
		t.Fatalf("failed to create tar file: %v", err)
	}
	tw := tar.NewWriter(f)

	// Valid dir
	if err := tw.WriteHeader(&tar.Header{
		Name:     "subdir/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatalf("write dir header: %v", err)
	}

	// Valid file inside dir
	content1 := []byte("nested file content")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "subdir/hello.txt",
		Mode:     0644,
		Size:     int64(len(content1)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write file header: %v", err)
	}
	if _, err := tw.Write(content1); err != nil {
		t.Fatalf("write file content: %v", err)
	}

	// Malicious relative path traversal entry
	evilContent := []byte("evil traversal payload")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "../escaped.txt",
		Mode:     0644,
		Size:     int64(len(evilContent)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write evil header: %v", err)
	}
	if _, err := tw.Write(evilContent); err != nil {
		t.Fatalf("write evil content: %v", err)
	}

	// Malicious absolute path entry
	if err := tw.WriteHeader(&tar.Header{
		Name:     "/tmp/abs_escaped.txt",
		Mode:     0644,
		Size:     int64(len(evilContent)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write abs evil header: %v", err)
	}
	if _, err := tw.Write(evilContent); err != nil {
		t.Fatalf("write abs evil content: %v", err)
	}

	_ = tw.Close()
	_ = f.Close()

	if err := ExtractTar(tarFile, destDir); err != nil {
		t.Fatalf("ExtractTar failed: %v", err)
	}

	// Verify valid file extracted
	extractedFile := filepath.Join(destDir, "subdir", "hello.txt")
	got, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("expected extracted file %s, err: %v", extractedFile, err)
	}
	if !bytes.Equal(got, content1) {
		t.Fatalf("content mismatch, got %s", string(got))
	}

	// Verify traversal entry was ignored and escaped.txt does not exist
	escapedPath := filepath.Join(tempDir, "escaped.txt")
	if _, err := os.Stat(escapedPath); !os.IsNotExist(err) {
		t.Fatalf("security violation: path traversal wrote to %s", escapedPath)
	}
}

func TestReceiverAutoExtract(t *testing.T) {
	tempDir := t.TempDir()
	keysDir := filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(keysDir, 0755)

	recvCert := filepath.Join(keysDir, "recv.crt")
	recvKey := filepath.Join(keysDir, "recv.key")
	recvFP, _ := tlsutil.GenerateCert("recv", 1, recvCert, recvKey)

	sendCert := filepath.Join(keysDir, "send.crt")
	sendKey := filepath.Join(keysDir, "send.key")
	sendFP, _ := tlsutil.GenerateCert("send", 1, sendCert, sendKey)

	incomingDir := filepath.Join(tempDir, "incoming")
	srv := NewServer(incomingDir, "127.0.0.1:0", recvCert, recvKey, []string{sendFP}, 1024*1024, nil)
	srv.SetAutoExtract(true)
	if err := srv.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer srv.Close()

	clientTLS, err := tlsutil.NewClientTLSConfig(sendCert, sendKey, []string{recvFP})
	if err != nil {
		t.Fatalf("client TLS config failed: %v", err)
	}

	conn, err := tls.Dial("tcp", srv.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Build a valid in-memory .tar
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	fileData := []byte("model parameters json")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "model_dir/params.json",
		Mode:     0644,
		Size:     int64(len(fileData)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar write header: %v", err)
	}
	if _, err := tw.Write(fileData); err != nil {
		t.Fatalf("tar write body: %v", err)
	}
	_ = tw.Close()

	tarBytes := tarBuf.Bytes()
	filename := "bundle.tar"
	if err := wire.WriteRequestHeader(conn, filename, uint64(len(tarBytes))); err != nil {
		t.Fatalf("WriteRequestHeader failed: %v", err)
	}
	if _, err := wire.SendStream(conn, bytes.NewReader(tarBytes), uint64(len(tarBytes))); err != nil {
		t.Fatalf("SendStream failed: %v", err)
	}
	if err := wire.ReadResponse(conn); err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}

	// Verify bundle.tar exists
	if _, err := os.Stat(filepath.Join(incomingDir, "bundle.tar")); err != nil {
		t.Fatalf("bundle.tar missing: %v", err)
	}

	// Verify auto-extracted model_dir/params.json exists
	extractedFile := filepath.Join(incomingDir, "bundle", "model_dir", "params.json")
	got, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("auto-extracted file missing at %s: %v", extractedFile, err)
	}
	if !bytes.Equal(got, fileData) {
		t.Fatalf("auto-extracted content mismatch: got %s, want %s", string(got), string(fileData))
	}
}
