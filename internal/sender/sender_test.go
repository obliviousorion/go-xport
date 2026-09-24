package sender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xport/internal/receiver"
	"xport/internal/tlsutil"
)

func TestTwoScanStabilityGate(t *testing.T) {
	tempDir := t.TempDir()
	queue := NewQueue(tempDir, 10, nil)
	scanner := NewScanner(tempDir, 50*time.Millisecond, queue)

	filePath := filepath.Join(tempDir, "shard_001.tar")

	// 1. Create file
	_ = os.WriteFile(filePath, []byte("data-part-1"), 0644)

	// Scan 1: file seen once, should not be in queue yet
	scanner.scanOnce()
	if queue.Len() != 0 {
		t.Fatalf("expected 0 files in queue after 1 scan, got %d", queue.Len())
	}

	// Scan 2: file size and modTime identical across two scans -> queued!
	scanner.scanOnce()
	if queue.Len() != 1 {
		t.Fatalf("expected 1 file in queue after 2 scans, got %d", queue.Len())
	}

	item, ok := queue.Pop()
	if !ok || item.Filename != "shard_001.tar" {
		t.Fatalf("unexpected item popped: %+v", item)
	}
}

func TestQuarantineAfterMaxAttempts(t *testing.T) {
	tempDir := t.TempDir()
	queue := NewQueue(tempDir, 3, nil) // 3 attempts max

	filePath := filepath.Join(tempDir, "poison.bin")
	_ = os.WriteFile(filePath, []byte("bad data"), 0644)

	item := FileItem{
		Filename: "poison.bin",
		Path:     filePath,
		Size:     8,
		ModTime:  time.Now(),
	}
	queue.Push(item)

	// Attempt 1
	it, ok := queue.Pop()
	if !ok {
		t.Fatal("failed to pop")
	}
	quarantined := queue.RecordFailure(it, errors.New("network drop"))
	if quarantined {
		t.Fatal("should not be quarantined on attempt 1")
	}

	// Attempt 2
	it, ok = queue.Pop()
	if !ok {
		t.Fatal("failed to pop")
	}
	quarantined = queue.RecordFailure(it, errors.New("checksum mismatch"))
	if quarantined {
		t.Fatal("should not be quarantined on attempt 2")
	}

	// Attempt 3 (reaches maxAttempts = 3)
	it, ok = queue.Pop()
	if !ok {
		t.Fatal("failed to pop")
	}
	quarantined = queue.RecordFailure(it, errors.New("timeout"))
	if !quarantined {
		t.Fatal("expected file to be quarantined on attempt 3")
	}

	// Verify file was moved to <dir>/.failed/poison.bin
	quarantinePath := filepath.Join(tempDir, ".failed", "poison.bin")
	if _, err := os.Stat(quarantinePath); err != nil {
		t.Fatalf("file not found in .failed/: %v", err)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("original file still exists at %s", filePath)
	}
}

func TestSenderReceiverEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	outboxDir := filepath.Join(tempDir, "outbox")
	incomingDir := filepath.Join(tempDir, "incoming")
	keysDir := filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(outboxDir, 0755)
	_ = os.MkdirAll(incomingDir, 0755)
	_ = os.MkdirAll(keysDir, 0755)

	recvCert := filepath.Join(keysDir, "recv.crt")
	recvKey := filepath.Join(keysDir, "recv.key")
	recvFP, err := tlsutil.GenerateCert("receiver", 365, recvCert, recvKey)
	if err != nil {
		t.Fatalf("receiver cert failed: %v", err)
	}

	sendCert := filepath.Join(keysDir, "send.crt")
	sendKey := filepath.Join(keysDir, "send.key")
	sendFP, err := tlsutil.GenerateCert("sender", 365, sendCert, sendKey)
	if err != nil {
		t.Fatalf("sender cert failed: %v", err)
	}

	// Start Receiver
	recvServer := receiver.NewServer(incomingDir, "127.0.0.1:0", recvCert, recvKey, []string{sendFP}, 1024*1024*10, nil)
	if err := recvServer.Start(); err != nil {
		t.Fatalf("recvServer.Start failed: %v", err)
	}
	defer recvServer.Close()

	receiverAddr := recvServer.Addr().String()

	// Setup Sender
	queue := NewQueue(outboxDir, 10, nil)
	scanner := NewScanner(outboxDir, 50*time.Millisecond, queue)
	pool := NewClientPool(outboxDir, receiverAddr, sendCert, sendKey, []string{recvFP}, 1, "archive", queue, scanner, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)
	defer pool.Stop()

	// Drop file into outbox: producer contract: hidden .tmp -> rename
	tmpPath := filepath.Join(outboxDir, ".shard_001.tar.tmp")
	finalPath := filepath.Join(outboxDir, "shard_001.tar")
	payload := []byte("important training batch checkpoint")
	_ = os.WriteFile(tmpPath, payload, 0644)
	_ = os.Rename(tmpPath, finalPath)

	// Scan twice to stabilize
	scanner.scanOnce()
	time.Sleep(20 * time.Millisecond)
	scanner.scanOnce()

	// Wait for transfer and commit
	recvPath := filepath.Join(incomingDir, "shard_001.tar")
	sentPath := filepath.Join(outboxDir, ".sent", "shard_001.tar")

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(recvPath); err == nil {
			if _, err := os.Stat(sentPath); err == nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	recvData, err := os.ReadFile(recvPath)
	if err != nil {
		t.Fatalf("received file does not exist: %v", err)
	}
	if string(recvData) != string(payload) {
		t.Fatalf("received content mismatch")
	}

	if _, err := os.Stat(sentPath); err != nil {
		t.Fatalf("file not archived to .sent/: %v", err)
	}
}
