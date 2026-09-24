//go:build windows

package monitor

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceExW = modkernel32.NewProc("GetDiskFreeSpaceExW")
)

// getPlatformDiskStats uses Windows kernel32 GetDiskFreeSpaceExW for Windows disk calculation.
func getPlatformDiskStats(path string) (DiskStats, error) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return DiskStats{}, err
	}
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes int64
	r1, _, err := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	if r1 == 0 {
		return DiskStats{}, fmt.Errorf("GetDiskFreeSpaceExW: %w", err)
	}
	freePct := 0
	if totalNumberOfBytes > 0 {
		freePct = int((float64(freeBytesAvailable) / float64(totalNumberOfBytes)) * 100)
	}
	return DiskStats{
		TotalBytes:  uint64(totalNumberOfBytes),
		FreeBytes:   uint64(freeBytesAvailable),
		FreePercent: freePct,
	}, nil
}
