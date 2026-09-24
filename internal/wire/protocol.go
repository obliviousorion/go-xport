package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Magic bytes for XP1 protocol: "XP1\n"
var MagicBytes = []byte{0x58, 0x50, 0x31, 0x0A}

const (
	AckByte  byte = 0x00
	NackByte byte = 0x01

	MaxFilenameLen = 200
	HashSize       = 32 // SHA-256 raw bytes
	BufferSize     = 1024 * 1024 // 1 MB buffer for high throughput streaming

	// Deadline requirements
	HandshakeTimeout = 10 * time.Second
	ReadWriteTimeout = 60 * time.Second
	ReceiverIdleTimeout = 2 * time.Minute
)

var (
	filenameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

	ErrInvalidMagic       = errors.New("invalid protocol magic header")
	ErrInvalidFilename    = errors.New("invalid filename: must match regex ^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$ and not end in .tmp or .part")
	ErrPayloadTooLarge    = errors.New("payload size exceeds maximum allowed size")
	ErrChecksumMismatch   = errors.New("sha-256 checksum mismatch")
	ErrUnexpectedResponse = errors.New("unexpected response code from receiver")
	ErrShortRead          = errors.New("unexpected EOF during transfer")
)

// ValidateFilename validates the filename according to the XP1 specification:
// - Basename only (reject path separators / or \)
// - Matches regex ^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$
// - Must not end in .tmp or .part
func ValidateFilename(name string) error {
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("%w: path separators not allowed", ErrInvalidFilename)
	}
	if strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".part") {
		return fmt.Errorf("%w: cannot end with .tmp or .part", ErrInvalidFilename)
	}
	if !filenameRegex.MatchString(name) {
		return ErrInvalidFilename
	}
	return nil
}

// WriteRequestHeader writes the XP1 header:
// 1. Magic bytes: "XP1\n" (4B)
// 2. Name Length: uint16 Big-Endian (2B)
// 3. Filename: UTF-8 string (L Bytes)
// 4. Payload Size: uint64 Big-Endian (8B)
func WriteRequestHeader(w io.Writer, filename string, payloadSize uint64) error {
	if err := ValidateFilename(filename); err != nil {
		return err
	}

	nameBytes := []byte(filename)
	nameLen := len(nameBytes)
	if nameLen > MaxFilenameLen {
		return fmt.Errorf("filename length %d exceeds max %d", nameLen, MaxFilenameLen)
	}

	header := make([]byte, 4+2+nameLen+8)
	copy(header[0:4], MagicBytes)
	binary.BigEndian.PutUint16(header[4:6], uint16(nameLen))
	copy(header[6:6+nameLen], nameBytes)
	binary.BigEndian.PutUint64(header[6+nameLen:6+nameLen+8], payloadSize)

	_, err := w.Write(header)
	return err
}

// ReadRequestHeader reads and parses the XP1 header:
// Returns the filename and payload size, or an error if invalid.
func ReadRequestHeader(r io.Reader, maxSize uint64) (string, uint64, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return "", 0, err
	}
	for i := 0; i < 4; i++ {
		if magic[i] != MagicBytes[i] {
			return "", 0, ErrInvalidMagic
		}
	}

	var nameLen uint16
	if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
		return "", 0, err
	}
	if nameLen == 0 || int(nameLen) > MaxFilenameLen {
		return "", 0, ErrInvalidFilename
	}

	nameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(r, nameBytes); err != nil {
		return "", 0, err
	}
	filename := string(nameBytes)
	if err := ValidateFilename(filename); err != nil {
		return "", 0, err
	}

	var payloadSize uint64
	if err := binary.Read(r, binary.BigEndian, &payloadSize); err != nil {
		return "", 0, err
	}
	if maxSize > 0 && payloadSize > maxSize {
		return filename, payloadSize, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, payloadSize, maxSize)
	}

	return filename, payloadSize, nil
}

// WriteAck writes the success byte 0x00
func WriteAck(w io.Writer) error {
	_, err := w.Write([]byte{AckByte})
	return err
}

// WriteNack writes the error byte 0x01 + 2-byte uint16 length + UTF-8 error string
func WriteNack(w io.Writer, msg string) error {
	msgBytes := []byte(msg)
	msgLen := len(msgBytes)
	if msgLen > 65535 {
		msgLen = 65535
		msgBytes = msgBytes[:msgLen]
	}

	buf := make([]byte, 1+2+msgLen)
	buf[0] = NackByte
	binary.BigEndian.PutUint16(buf[1:3], uint16(msgLen))
	copy(buf[3:], msgBytes)

	_, err := w.Write(buf)
	return err
}

// ReadResponse reads the response frame from the receiver.
// Returns nil on ACK (0x00), or an error containing the NACK message (0x01).
func ReadResponse(r io.Reader) error {
	code := make([]byte, 1)
	if _, err := io.ReadFull(r, code); err != nil {
		return err
	}

	switch code[0] {
	case AckByte:
		return nil
	case NackByte:
		var msgLen uint16
		if err := binary.Read(r, binary.BigEndian, &msgLen); err != nil {
			return fmt.Errorf("failed to read nack message length: %w", err)
		}
		msgBytes := make([]byte, msgLen)
		if _, err := io.ReadFull(r, msgBytes); err != nil {
			return fmt.Errorf("failed to read nack message: %w", err)
		}
		return fmt.Errorf("receiver nack: %s", string(msgBytes))
	default:
		return fmt.Errorf("%w: byte 0x%02x", ErrUnexpectedResponse, code[0])
	}
}

// DeadlineConn wraps a net.Conn to refresh read/write deadlines on every operation.
type DeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func NewDeadlineConn(conn net.Conn, timeout time.Duration) *DeadlineConn {
	return &DeadlineConn{Conn: conn, timeout: timeout}
}

func (c *DeadlineConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *DeadlineConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}

// SendStream streams payload from reader to writer using a 1 MB buffer,
// simultaneously calculating SHA-256, and appends the 32-byte SHA-256 hash trailer.
func SendStream(w io.Writer, r io.Reader, payloadSize uint64) ([]byte, error) {
	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	buf := make([]byte, BufferSize)
	copied, err := io.CopyBuffer(w, tee, buf)
	if err != nil {
		return nil, err
	}
	if uint64(copied) != payloadSize {
		return nil, fmt.Errorf("%w: expected %d bytes, copied %d", ErrShortRead, payloadSize, copied)
	}

	sum := hasher.Sum(nil)
	if _, err := w.Write(sum); err != nil {
		return nil, fmt.Errorf("failed to write checksum trailer: %w", err)
	}

	return sum, nil
}

// ReceiveStream reads exactly payloadSize bytes into dst using a 1 MB buffer,
// calculating SHA-256, then reads the 32-byte hash trailer and verifies integrity.
func ReceiveStream(dst io.Writer, src io.Reader, payloadSize uint64) error {
	hasher := sha256.New()
	tee := io.TeeReader(io.LimitReader(src, int64(payloadSize)), hasher)

	buf := make([]byte, BufferSize)
	copied, err := io.CopyBuffer(dst, tee, buf)
	if err != nil {
		return err
	}
	if uint64(copied) != payloadSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrShortRead, payloadSize, copied)
	}

	trailer := make([]byte, HashSize)
	if _, err := io.ReadFull(src, trailer); err != nil {
		return fmt.Errorf("failed to read checksum trailer: %w", err)
	}

	calculated := hasher.Sum(nil)
	for i := 0; i < HashSize; i++ {
		if calculated[i] != trailer[i] {
			return ErrChecksumMismatch
		}
	}

	return nil
}

// ParseByteSize parses a human-readable byte size string (e.g. "64GiB", "100MB", "1024")
func ParseByteSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty byte size")
	}

	// Find where units begin
	idx := 0
	for idx < len(s) && (unicode.IsDigit(rune(s[idx])) || s[idx] == '.') {
		idx++
	}

	numStr := strings.TrimSpace(s[:idx])
	unitStr := strings.TrimSpace(strings.ToUpper(s[idx:]))

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in byte size %q: %w", s, err)
	}
	if val < 0 {
		return 0, fmt.Errorf("negative byte size %q", s)
	}

	var multiplier float64 = 1
	switch unitStr {
	case "", "B":
		multiplier = 1
	case "K", "KB":
		multiplier = 1e3
	case "KIB":
		multiplier = 1024
	case "M", "MB":
		multiplier = 1e6
	case "MIB":
		multiplier = 1024 * 1024
	case "G", "GB":
		multiplier = 1e9
	case "GIB":
		multiplier = 1024 * 1024 * 1024
	case "T", "TB":
		multiplier = 1e12
	case "TIB":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown byte unit %q", unitStr)
	}

	return uint64(val * multiplier), nil
}
