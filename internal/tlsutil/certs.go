package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// FingerprintDER computes the lowercase hex-encoded SHA-256 fingerprint of raw DER certificate bytes.
func FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// GenerateCert generates an ECDSA P-256 private key and self-signed X.509 certificate.
// It saves them to certPath and keyPath in PEM format, and returns the lowercase hex SHA-256 fingerprint.
func GenerateCert(name string, days int, certPath, keyPath string) (string, error) {
	if days <= 0 {
		days = 3650
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ecdsa key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"xport"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost", name},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure parent directories exist
	if certDir := filepath.Dir(certPath); certDir != "" {
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %w", certDir, err)
		}
	}
	if keyDir := filepath.Dir(keyPath); keyDir != "" {
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %w", keyDir, err)
		}
	}

	// Write certificate PEM
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to open %s for writing: %w", certPath, err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", fmt.Errorf("failed to write certificate pem: %w", err)
	}

	// Write private key PEM
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ecdsa private key: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open %s for writing: %w", keyPath, err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return "", fmt.Errorf("failed to write private key pem: %w", err)
	}

	fp := FingerprintDER(derBytes)
	return fp, nil
}

// LoadCertFingerprint reads a PEM certificate file and returns its lowercase hex SHA-256 fingerprint.
func LoadCertFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("failed to parse certificate pem block from %s", certPath)
	}

	return FingerprintDER(block.Bytes), nil
}
