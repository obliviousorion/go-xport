//go:build !windows

package monitor

import (
	"fmt"
	"syscall"
)

// getPlatformDiskStats uses standard library syscall.Statfs for zero-dependency Linux/Unix disk calculation.
func getPlatformDiskStats(path string) (DiskStats, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return DiskStats{}, fmt.Errorf("statfs %s: %w", path, err)
	}

	freeBytes := stat.Bavail * uint64(stat.Bsize)
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freePct := 0
	if totalBytes > 0 {
		freePct = int((float64(freeBytes) / float64(totalBytes)) * 100)
	}

	return DiskStats{
		TotalBytes:  totalBytes,
		FreeBytes:   freeBytes,
		FreePercent: freePct,
	}, nil
}
