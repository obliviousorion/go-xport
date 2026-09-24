package wire

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestValidateFilename(t *testing.T) {
	valid := []string{
		"shard-00001.tar",
		"model_weights.bin",
		"data.123",
		"A",
		"shard_001.tar",
		"dataset-part-001.parquet",
	}
	for _, f := range valid {
		if err := ValidateFilename(f); err != nil {
			t.Errorf("expected valid filename %q, got error: %v", f, err)
		}
	}

	invalid := []string{
		"",
		"../shard.tar",
		"subdir/shard.tar",
		"sub\\shard.tar",
		"shard.tmp",
		"shard.part",
		".hidden",
		"-leading-dash",
		"_leading_underscore",
		strings.Repeat("a", 201),
	}
	for _, f := range invalid {
		if err := ValidateFilename(f); err == nil {
			t.Errorf("expected error for invalid filename %q, got nil", f)
		}
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	filename := "shard-00042.tar"
	payloadSize := uint64(1024 * 1024 * 50) // 50MB

	if err := WriteRequestHeader(&buf, filename, payloadSize); err != nil {
		t.Fatalf("WriteRequestHeader failed: %v", err)
	}

	gotName, gotSize, err := ReadRequestHeader(&buf, 1024*1024*100)
	if err != nil {
		t.Fatalf("ReadRequestHeader failed: %v", err)
	}

	if gotName != filename {
		t.Errorf("expected filename %q, got %q", filename, gotName)
	}
	if gotSize != payloadSize {
		t.Errorf("expected size %d, got %d", payloadSize, gotSize)
	}
}

func TestHeaderMaxSizeExceeded(t *testing.T) {
	var buf bytes.Buffer
	filename := "shard-00042.tar"
	payloadSize := uint64(2000)

	if err := WriteRequestHeader(&buf, filename, payloadSize); err != nil {
		t.Fatalf("WriteRequestHeader failed: %v", err)
	}

	_, _, err := ReadRequestHeader(&buf, 1000)
	if err == nil {
		t.Fatal("expected error due to max size exceeded, got nil")
	}
}

func TestStreamRoundTrip(t *testing.T) {
	// Generate 2.5 MB of random data to test across 1MB buffer boundaries
	size := 2500000
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	var pipe bytes.Buffer
	sum, err := SendStream(&pipe, bytes.NewReader(payload), uint64(size))
	if err != nil {
		t.Fatalf("SendStream failed: %v", err)
	}

	expectedSum := sha256.Sum256(payload)
	if !bytes.Equal(sum, expectedSum[:]) {
		t.Fatalf("returned checksum mismatch")
	}

	var received bytes.Buffer
	if err := ReceiveStream(&received, &pipe, uint64(size)); err != nil {
		t.Fatalf("ReceiveStream failed: %v", err)
	}

	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("received bytes do not match sent payload")
	}
}

func TestStreamChecksumMismatch(t *testing.T) {
	payload := []byte("hello distributed ML pipeline")
	size := uint64(len(payload))

	var pipe bytes.Buffer
	_, err := SendStream(&pipe, bytes.NewReader(payload), size)
	if err != nil {
		t.Fatalf("SendStream failed: %v", err)
	}

	// Corrupt one byte of trailer
	b := pipe.Bytes()
	b[len(b)-1] ^= 0xFF

	var received bytes.Buffer
	err = ReceiveStream(&received, bytes.NewReader(b), size)
	if err != ErrChecksumMismatch {
		t.Fatalf("expected ErrChecksumMismatch, got: %v", err)
	}
}

func TestAckNackRoundTrip(t *testing.T) {
	// Test ACK
	var buf bytes.Buffer
	if err := WriteAck(&buf); err != nil {
		t.Fatalf("WriteAck failed: %v", err)
	}
	if err := ReadResponse(&buf); err != nil {
		t.Fatalf("ReadResponse expected nil for ACK, got: %v", err)
	}

	// Test NACK
	buf.Reset()
	errMsg := "disk quota exceeded"
	if err := WriteNack(&buf, errMsg); err != nil {
		t.Fatalf("WriteNack failed: %v", err)
	}
	err := ReadResponse(&buf)
	if err == nil || !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("expected error containing %q, got: %v", errMsg, err)
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"1024", 1024},
		{"1KB", 1000},
		{"1KiB", 1024},
		{"64GiB", 64 * 1024 * 1024 * 1024},
		{"100MB", 100 * 1000 * 1000},
		{"100MiB", 100 * 1024 * 1024},
		{"1.5GB", 1500000000},
	}

	for _, tc := range tests {
		got, err := ParseByteSize(tc.input)
		if err != nil {
			t.Errorf("ParseByteSize(%q) unexpected error: %v", tc.input, err)
		} else if got != tc.expected {
			t.Errorf("ParseByteSize(%q) = %d, expected %d", tc.input, got, tc.expected)
		}
	}
}
