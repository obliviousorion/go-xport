package tlsutil

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNoPeerCert          = errors.New("no peer certificate presented")
	ErrPeerCertNotPinned   = errors.New("peer certificate fingerprint not recognized")
	ErrNoAllowedPeers      = errors.New("no allowed peer fingerprints configured")
)

// NormalizeFingerprint standardizes fingerprint strings by stripping colons,
// spaces, and converting to lowercase hex.
func NormalizeFingerprint(fp string) string {
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return strings.ToLower(strings.TrimSpace(fp))
}

// ParseFingerprints normalizes a slice of fingerprint strings or comma-separated fingerprints.
func ParseFingerprints(list []string) []string {
	var result []string
	for _, item := range list {
		for _, part := range strings.Split(item, ",") {
			norm := NormalizeFingerprint(part)
			if norm != "" {
				result = append(result, norm)
			}
		}
	}
	return result
}

// MakeVerifyPeerCertificate builds a VerifyPeerCertificate callback that matches
// the peer certificate DER SHA-256 fingerprint against allowed fingerprints using
// subtle.ConstantTimeCompare.
func MakeVerifyPeerCertificate(allowedFingerprints []string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	normalizedAllowed := ParseFingerprints(allowedFingerprints)

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoPeerCert
		}
		if len(normalizedAllowed) == 0 {
			return ErrNoAllowedPeers
		}

		peerFP := FingerprintDER(rawCerts[0])
		peerFPBytes := []byte(peerFP)

		matched := false
		for _, allowed := range normalizedAllowed {
			allowedBytes := []byte(allowed)
			if len(peerFPBytes) == len(allowedBytes) && subtle.ConstantTimeCompare(peerFPBytes, allowedBytes) == 1 {
				matched = true
				break
			}
		}

		if !matched {
			return fmt.Errorf("%w: presented %s", ErrPeerCertNotPinned, peerFP)
		}

		return nil
	}
}

// NewServerTLSConfig creates a TLS 1.3 server config that requires mutual TLS
// and verifies peer certificates against the allowed fingerprints.
func NewServerTLSConfig(certFile, keyFile string, allowedPeerFingerprints []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		// Bypass traditional CA verification & expiry checks as specified:
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: MakeVerifyPeerCertificate(allowedPeerFingerprints),
	}, nil
}

// NewClientTLSConfig creates a TLS 1.3 client config that presents the client cert
// and verifies the server's certificate against the allowed fingerprints.
func NewClientTLSConfig(certFile, keyFile string, allowedPeerFingerprints []string) (*tls.Config, error) {
	var certs []tls.Certificate
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client keypair: %w", err)
		}
		certs = append(certs, cert)
	}

	return &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS13,
		// Bypass traditional CA verification & expiry checks as specified:
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: MakeVerifyPeerCertificate(allowedPeerFingerprints),
	}, nil
}
