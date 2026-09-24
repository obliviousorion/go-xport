package receiver

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BootCleanup cleans up all lingering .tmp files inside <dir>/.staging/ from previous aborted runs.
func BootCleanup(incomingDir string) error {
	stagingDir := filepath.Join(incomingDir, ".staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("failed to create staging dir %s: %w", stagingDir, err)
	}

	return filepath.Walk(stagingDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tmp") {
			_ = os.Remove(path)
		}
		return nil
	})
}

// CreateStagedFile creates an isolated temporary file inside <incomingDir>/.staging/<crypto-rand-hex>.tmp
// with permissions 0644. Since .staging is inside the root of incomingDir, os.Rename will always be on the
// same filesystem.
func CreateStagedFile(incomingDir string) (*os.File, string, error) {
	stagingDir := filepath.Join(incomingDir, ".staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return nil, "", fmt.Errorf("failed to ensure staging directory: %w", err)
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, "", fmt.Errorf("crypto rand failed: %w", err)
	}
	stagedName := hex.EncodeToString(randBytes) + ".tmp"
	stagedPath := filepath.Join(stagingDir, stagedName)

	f, err := os.OpenFile(stagedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open staging file %s: %w", stagedPath, err)
	}

	return f, stagedPath, nil
}
