package receiver

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xport/internal/wire"
)

// CommitBarrier executes the full durability barrier:
// 1. file.Sync() to flush file content and inode metadata
// 2. file.Close()
// 3. os.Rename(stagedPath, targetPath) to atomically place into incoming folder
// 4. dir.Sync() to persist directory inode block updates
// 5. If autoExtract, extract .tar archive before ACK
// 6. Transmit 0x00 ACK to the sender
// Returns the committed target path and any error encountered.
func CommitBarrier(stagedFile *os.File, stagedPath, incomingDir, filename, collisionPolicy string, autoExtract bool, conn io.Writer) (string, error) {
	// 1. Sync staged file
	if err := stagedFile.Sync(); err != nil {
		_ = stagedFile.Close()
		_ = os.Remove(stagedPath)
		return "", fmt.Errorf("failed to sync staged file: %w", err)
	}

	// 2. Close staged file
	if err := stagedFile.Close(); err != nil {
		_ = os.Remove(stagedPath)
		return "", fmt.Errorf("failed to close staged file: %w", err)
	}

	// Handle collision if target already exists
	targetPath := filepath.Join(incomingDir, filename)
	if _, err := os.Stat(targetPath); err == nil {
		switch collisionPolicy {
		case "reject":
			_ = os.Remove(stagedPath)
			return "", fmt.Errorf("file %q already exists in destination", filename)
		case "overwrite":
			// Proceed with standard atomic overwrite
		case "rename":
			fallthrough
		default:
			targetPath = filepath.Join(incomingDir, fmt.Sprintf("%s.%d", filename, time.Now().UnixNano()))
		}
	}

	// 3. Atomic rename to target path in incoming directory
	if err := os.Rename(stagedPath, targetPath); err != nil {
		_ = os.Remove(stagedPath)
		return "", fmt.Errorf("failed to atomically rename staged file: %w", err)
	}

	// 4. Open destination directory and sync directory inode blocks
	dirFile, err := os.Open(incomingDir)
	if err != nil {
		return "", fmt.Errorf("failed to open destination directory for sync: %w", err)
	}
	syncErr := dirFile.Sync()
	_ = dirFile.Close()
	if syncErr != nil {
		return "", fmt.Errorf("failed to sync destination directory inode: %w", syncErr)
	}

	// 5. Extract tar archive if autoExtract requested
	if autoExtract && strings.HasSuffix(filename, ".tar") {
		extractDir := filepath.Join(incomingDir, strings.TrimSuffix(filepath.Base(targetPath), ".tar"))
		if err := ExtractTar(targetPath, extractDir); err != nil {
			fmt.Fprintf(os.Stderr, "[receiver] warning: auto-extract failed for %s: %v\n", targetPath, err)
		}
	}

	// 6. Transmit 0x00 ACK to sender
	if err := wire.WriteAck(conn); err != nil {
		return "", fmt.Errorf("failed to write 0x00 ACK to sender: %w", err)
	}

	return targetPath, nil
}

// ExtractTar extracts a .tar archive into destDir with Zip-Slip path traversal protection.
func ExtractTar(tarPath, destDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		cleanName := filepath.Clean(hdr.Name)
		if filepath.IsAbs(cleanName) {
			continue // Prevent path traversal
		}

		target := filepath.Join(destDir, cleanName)
		rel, err := filepath.Rel(destDir, target)
		if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
			continue // Prevent escaping destDir
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return err
			}
			_ = out.Close()
		}
	}
	return nil
}
