package sender

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"xport/internal/wire"
)

type fileScanState struct {
	size             int64
	modTime          time.Time
	consecutiveScans int
	isQueued         bool
}

type FileItem struct {
	Filename string
	Path     string
	Size     int64
	ModTime  time.Time
}

type Scanner struct {
	watchDir string
	interval time.Duration
	queue    *Queue

	mu            sync.Mutex
	states        map[string]*fileScanState
	ignoredWarned map[string]struct{}
	stopCh        chan struct{}
	stopOnce      sync.Once
}

func NewScanner(watchDir string, interval time.Duration, queue *Queue) *Scanner {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	return &Scanner{
		watchDir:      watchDir,
		interval:      interval,
		queue:         queue,
		states:        make(map[string]*fileScanState),
		ignoredWarned: make(map[string]struct{}),
		stopCh:        make(chan struct{}),
	}
}

func (s *Scanner) Start() {
	go s.scanLoop()
}

func (s *Scanner) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

func (s *Scanner) scanLoop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Initial scan immediately
	s.scanOnce()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scanOnce()
		}
	}
}

// scanOnce performs one directory scan and checks 2-scan stability.
func (s *Scanner) scanOnce() {
	entries, err := os.ReadDir(s.watchDir)
	if err != nil {
		log.Printf("[scanner] error reading watch dir %s: %v", s.watchDir, err)
		return
	}

	currentFiles := make(map[string]struct{})
	var stableFiles []FileItem

	s.mu.Lock()
	for _, entry := range entries {
		name := entry.Name()

		// Flat directory: ignore subdirectories
		if entry.IsDir() {
			continue
		}

		// Security: reject symlinks in watch directory to prevent arbitrary file exfiltration
		if entry.Type()&os.ModeSymlink != 0 {
			if _, warned := s.ignoredWarned[name]; !warned {
				log.Printf("[scanner] SECURITY: ignoring symlink %q in watch directory to prevent exfiltration", name)
				s.ignoredWarned[name] = struct{}{}
			}
			currentFiles[name] = struct{}{}
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}

		// Ignore hidden files (starts with .)
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Reject files ending in .tmp or .part or invalid filename
		if err := wire.ValidateFilename(name); err != nil {
			if !strings.HasSuffix(name, ".tmp") && !strings.HasSuffix(name, ".part") {
				if _, warned := s.ignoredWarned[name]; !warned {
					log.Printf("[scanner] WARN: ignoring file %q with invalid name format: %v", name, err)
					s.ignoredWarned[name] = struct{}{}
				}
				currentFiles[name] = struct{}{}
			}
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		currentFiles[name] = struct{}{}
		size := info.Size()
		modTime := info.ModTime()

		state, exists := s.states[name]
		if !exists {
			// First scan seen
			s.states[name] = &fileScanState{
				size:             size,
				modTime:          modTime,
				consecutiveScans: 1,
				isQueued:         false,
			}
		} else {
			// Check if size and modTime are completely identical across two consecutive scans
			if state.size == size && state.modTime.Equal(modTime) {
				state.consecutiveScans++
				if state.consecutiveScans >= 2 && !state.isQueued {
					state.isQueued = true
					stableFiles = append(stableFiles, FileItem{
						Filename: name,
						Path:     filepath.Join(s.watchDir, name),
						Size:     size,
						ModTime:  modTime,
					})
				}
			} else {
				// File modified between scans: reset stability gate
				state.size = size
				state.modTime = modTime
				state.consecutiveScans = 1
			}
		}
	}

	// Remove disappeared files from states map
	for name := range s.states {
		if _, ok := currentFiles[name]; !ok {
			delete(s.states, name)
		}
	}
	for name := range s.ignoredWarned {
		if _, ok := currentFiles[name]; !ok {
			delete(s.ignoredWarned, name)
		}
	}
	s.mu.Unlock()

	// Sort stable files by oldest modification time first
	sort.Slice(stableFiles, func(i, j int) bool {
		return stableFiles[i].ModTime.Before(stableFiles[j].ModTime)
	})

	for _, item := range stableFiles {
		s.queue.Push(item)
	}
}

// MarkCompleted removes a file from the scanner tracking state.
func (s *Scanner) MarkCompleted(filename string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, filename)
}
