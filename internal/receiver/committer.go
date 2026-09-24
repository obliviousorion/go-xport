package receiver

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"xport/internal/wire"
)

// CommitBarrier executes the full durability barrier:
// 1. file.Sync() to flush file content and inode metadata
// 2. file.Close()
// 3. os.Rename(stagedPath, targetPath) to atomically place into incoming folder
// 4. dir.Sync() to persist directory inode block updates
// 5. Transmit 0x00 ACK to the sender
func CommitBarrier(stagedFile *os.File, stagedPath, incomingDir, filename, collisionPolicy string, conn io.Writer) error {
	// 1. Sync staged file
	if err := stagedFile.Sync(); err != nil {
		_ = stagedFile.Close()
		_ = os.Remove(stagedPath)
		return fmt.Errorf("failed to sync staged file: %w", err)
	}

	// 2. Close staged file
	if err := stagedFile.Close(); err != nil {
		_ = os.Remove(stagedPath)
		return fmt.Errorf("failed to close staged file: %w", err)
	}

	// Handle collision if target already exists
	targetPath := filepath.Join(incomingDir, filename)
	if _, err := os.Stat(targetPath); err == nil {
		switch collisionPolicy {
		case "reject":
			_ = os.Remove(stagedPath)
			return fmt.Errorf("file %q already exists in destination", filename)
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
		return fmt.Errorf("failed to atomically rename staged file: %w", err)
	}

	// 4. Open destination directory and sync directory inode blocks
	dirFile, err := os.Open(incomingDir)
	if err != nil {
		return fmt.Errorf("failed to open destination directory for sync: %w", err)
	}
	syncErr := dirFile.Sync()
	_ = dirFile.Close()
	if syncErr != nil {
		return fmt.Errorf("failed to sync destination directory inode: %w", syncErr)
	}

	// 5. Transmit 0x00 ACK to sender
	if err := wire.WriteAck(conn); err != nil {
		return fmt.Errorf("failed to write 0x00 ACK to sender: %w", err)
	}

	return nil
}
