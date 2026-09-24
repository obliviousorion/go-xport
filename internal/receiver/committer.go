package receiver

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xport/internal/wire"
)

// atomicCommitNoReplace atomically places stagedPath at targetPath without overwriting an existing file.
// If targetPath already exists, it returns os.ErrExist.
func atomicCommitNoReplace(stagedPath, targetPath string) error {
	// os.Link creates targetPath atomically and fails with os.ErrExist if it already exists on POSIX.
	if err := os.Link(stagedPath, targetPath); err != nil {
		return err
	}
	_ = os.Remove(stagedPath)
	return nil
}

// CommitBarrier executes the full durability barrier:
// 1. file.Sync() to flush file content and inode metadata
// 2. file.Close()
// 3. Atomic placement into incoming directory respecting collisionPolicy:
//   - reject: fail atomically if target exists without overwriting
//   - rename: atomically place with timestamp suffix if collision occurs
//   - overwrite: atomic replace via os.Rename
//
// 4. dir.Sync() to persist directory inode block updates
// 5. If autoExtract, extract .tar archive before ACK:
//   - Enforces extraction ratio quota and absolute cap
//   - Respects collision policy on target extract directory
//   - fsyncs all extracted files and directory inodes
//   - If extraction fails, cleans up and does NOT send ACK
//
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

	// 3. Atomically commit staged file to target path
	targetPath := filepath.Join(incomingDir, filename)
	switch collisionPolicy {
	case "reject":
		if err := atomicCommitNoReplace(stagedPath, targetPath); err != nil {
			_ = os.Remove(stagedPath)
			if errors.Is(err, os.ErrExist) {
				return "", fmt.Errorf("PERM: file %q already exists in destination", filename)
			}
			return "", fmt.Errorf("failed to commit staged file: %w", err)
		}
	case "overwrite":
		if err := os.Rename(stagedPath, targetPath); err != nil {
			_ = os.Remove(stagedPath)
			return "", fmt.Errorf("failed to atomically rename staged file: %w", err)
		}
	case "rename":
		fallthrough
	default:
		// Attempt atomic placement without rename first
		if err := atomicCommitNoReplace(stagedPath, targetPath); err != nil {
			if errors.Is(err, os.ErrExist) {
				placed := false
				for attempt := 0; attempt < 1000; attempt++ {
					altPath := filepath.Join(incomingDir, fmt.Sprintf("%s.%d", filename, time.Now().UnixNano()))
					if linkErr := atomicCommitNoReplace(stagedPath, altPath); linkErr == nil {
						targetPath = altPath
						placed = true
						break
					} else if !errors.Is(linkErr, os.ErrExist) {
						_ = os.Remove(stagedPath)
						return "", fmt.Errorf("failed to commit staged file with rename: %w", linkErr)
					}
					time.Sleep(100 * time.Microsecond)
				}
				if !placed {
					_ = os.Remove(stagedPath)
					return "", fmt.Errorf("failed to find available collision rename slot for %s", filename)
				}
			} else {
				_ = os.Remove(stagedPath)
				return "", fmt.Errorf("failed to commit staged file: %w", err)
			}
		}
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
		baseDir := strings.TrimSuffix(filepath.Base(targetPath), ".tar")
		extractDir := filepath.Join(incomingDir, baseDir)

		// Apply collision policy to extraction destination directory
		switch collisionPolicy {
		case "reject":
			if _, err := os.Stat(extractDir); err == nil {
				_ = os.Remove(targetPath)
				return "", fmt.Errorf("PERM: extraction directory %q already exists in destination", baseDir)
			}
		case "overwrite":
			_ = os.RemoveAll(extractDir)
		case "rename":
			fallthrough
		default:
			if _, err := os.Stat(extractDir); err == nil {
				extractDir = filepath.Join(incomingDir, fmt.Sprintf("%s.%d", baseDir, time.Now().UnixNano()))
			}
		}

		// Stage extraction in .staging/ to ensure partial extraction is never exposed
		stagingExtractDir := filepath.Join(incomingDir, ".staging", fmt.Sprintf("extract-%d.tmp", time.Now().UnixNano()))
		_ = os.MkdirAll(stagingExtractDir, 0755)

		// Enforce expansion quota: max 10x tar size, minimum floor 50MB
		tarStat, statErr := os.Stat(targetPath)
		var maxExtractBytes uint64 = 50 * 1024 * 1024
		if statErr == nil && uint64(tarStat.Size())*10 > maxExtractBytes {
			maxExtractBytes = uint64(tarStat.Size()) * 10
		}

		if err := ExtractTarWithLimit(targetPath, stagingExtractDir, maxExtractBytes); err != nil {
			_ = os.RemoveAll(stagingExtractDir)
			_ = os.Remove(targetPath)
			return "", fmt.Errorf("auto-extract failed: %w", err)
		}

		// Atomically move staging extract dir to extractDir
		if err := os.Rename(stagingExtractDir, extractDir); err != nil {
			_ = os.RemoveAll(stagingExtractDir)
			_ = os.Remove(targetPath)
			return "", fmt.Errorf("failed to commit extracted directory: %w", err)
		}

		// Sync incoming directory inode
		if dFile, err := os.Open(incomingDir); err == nil {
			_ = dFile.Sync()
			_ = dFile.Close()
		}
	}

	// 6. Transmit 0x00 ACK to sender only after everything (including extraction) succeeds
	if err := wire.WriteAck(conn); err != nil {
		return "", fmt.Errorf("failed to write 0x00 ACK to sender: %w", err)
	}

	return targetPath, nil
}

// ExtractTar extracts a .tar archive into destDir with Zip-Slip path traversal protection.
func ExtractTar(tarPath, destDir string) error {
	return ExtractTarWithLimit(tarPath, destDir, 0)
}

// ExtractTarWithLimit extracts a .tar archive into destDir with:
// - Zip-Slip path traversal protection
// - Decompression bomb / expansion quota defense
// - Fsync on all extracted files and directory inodes
func ExtractTarWithLimit(tarPath, destDir string, maxExtractBytes uint64) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	tr := tar.NewReader(f)
	var totalExtracted uint64
	var createdDirs []string

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
			createdDirs = append(createdDirs, target)
		case tar.TypeReg, tar.TypeRegA, tar.TypeGNUSparse:
			parentDir := filepath.Dir(target)
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				return err
			}
			createdDirs = append(createdDirs, parentDir)

			if maxExtractBytes > 0 && totalExtracted+uint64(hdr.Size) > maxExtractBytes {
				return fmt.Errorf("PERM: extraction quota exceeded (%d bytes > limit %d)", totalExtracted+uint64(hdr.Size), maxExtractBytes)
			}

			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode().Perm())
			if err != nil {
				return err
			}

			var limitReader io.Reader = tr
			if maxExtractBytes > 0 {
				remaining := maxExtractBytes - totalExtracted
				limitReader = io.LimitReader(tr, int64(remaining)+1)
			}

			copied, copyErr := io.Copy(out, limitReader)
			totalExtracted += uint64(copied)

			if maxExtractBytes > 0 && totalExtracted > maxExtractBytes {
				_ = out.Close()
				return fmt.Errorf("PERM: extraction quota exceeded (%d bytes > limit %d)", totalExtracted, maxExtractBytes)
			}

			if copyErr != nil {
				_ = out.Close()
				return copyErr
			}

			// Fsync file content and metadata
			if err := out.Sync(); err != nil {
				_ = out.Close()
				return fmt.Errorf("failed to fsync extracted file %s: %w", target, err)
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}

	// Fsync all created directory inodes
	for _, dPath := range createdDirs {
		df, err := os.Open(dPath)
		if err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}

	return nil
}
