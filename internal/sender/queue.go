package sender

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"xport/internal/monitor"
)

type Queue struct {
	watchDir    string
	maxAttempts int
	tracker     *monitor.Tracker

	mu          sync.Mutex
	cond        *sync.Cond
	items       []FileItem
	inQueue     map[string]struct{}
	attempts    map[string]int
	failedCount int
	stopped     bool
}

func NewQueue(watchDir string, maxAttempts int, tracker *monitor.Tracker) *Queue {
	if maxAttempts <= 0 {
		maxAttempts = 10
	}

	q := &Queue{
		watchDir:    watchDir,
		maxAttempts: maxAttempts,
		tracker:     tracker,
		inQueue:     make(map[string]struct{}),
		attempts:    make(map[string]int),
	}
	q.cond = sync.NewCond(&q.mu)

	// Count existing files in .failed/
	q.updateFailedCount()

	return q
}

func (q *Queue) updateFailedCount() {
	failedDir := filepath.Join(q.watchDir, ".failed")
	entries, err := os.ReadDir(failedDir)
	if err == nil {
		count := 0
		for _, e := range entries {
			if !e.IsDir() {
				count++
			}
		}
		q.failedCount = count
	}
	if q.tracker != nil {
		q.tracker.SetQueueCounts(len(q.items), q.failedCount)
	}
}

// Push adds an item to the queue, preserving sort order by ModTime (oldest first).
func (q *Queue) Push(item FileItem) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.stopped {
		return
	}

	if _, exists := q.inQueue[item.Filename]; exists {
		return
	}

	q.items = append(q.items, item)
	q.inQueue[item.Filename] = struct{}{}

	// Sort items by oldest modification time first
	sort.Slice(q.items, func(i, j int) bool {
		return q.items[i].ModTime.Before(q.items[j].ModTime)
	})

	if q.tracker != nil {
		q.tracker.SetQueueCounts(len(q.items), q.failedCount)
	}

	q.cond.Signal()
}

// Requeue puts an item back to the queue (e.g. after a transport/dial error)
// without incrementing its failure attempts count.
func (q *Queue) Requeue(item FileItem) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.stopped {
		return
	}

	if _, exists := q.inQueue[item.Filename]; !exists {
		q.items = append([]FileItem{item}, q.items...)
		q.inQueue[item.Filename] = struct{}{}
		sort.Slice(q.items, func(i, j int) bool {
			return q.items[i].ModTime.Before(q.items[j].ModTime)
		})
		if q.tracker != nil {
			q.tracker.SetQueueCounts(len(q.items), q.failedCount)
		}
		q.cond.Signal()
	}
}

// Pop retrieves the next file in FIFO order. Blocks if queue is empty until an item is pushed or queue stopped.
// Returns item, ok (false if stopped).
func (q *Queue) Pop() (FileItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for len(q.items) == 0 && !q.stopped {
		q.cond.Wait()
	}

	if q.stopped && len(q.items) == 0 {
		return FileItem{}, false
	}

	item := q.items[0]
	q.items = q.items[1:]
	delete(q.inQueue, item.Filename)

	if q.tracker != nil {
		q.tracker.SetQueueCounts(len(q.items), q.failedCount)
	}

	return item, true
}

// RecordSuccess clears failure tracking for the file.
func (q *Queue) RecordSuccess(filename string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.attempts, filename)
}

// RecordFailure increments attempts for the item. If attempts reach maxAttempts,
// the file is quarantined to <dir>/.failed/<filename>. Otherwise, it is requeued.
// Returns true if quarantined, false if requeued for retry.
// Quarantine immediately moves an item to .failed/ without incrementing failure attempts
// (used for permanent non-retryable rejections like file too large or invalid filename).
func (q *Queue) Quarantine(item FileItem, reason error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.quarantineLocked(item, reason, 0)
}

func (q *Queue) quarantineLocked(item FileItem, reason error, count int) {
	failedDir := filepath.Join(q.watchDir, ".failed")
	if err := os.MkdirAll(failedDir, 0755); err != nil {
		log.Printf("[queue] failed to create .failed dir: %v", err)
	}
	failedPath := filepath.Join(failedDir, item.Filename)
	if _, err := os.Stat(failedPath); err == nil {
		failedPath = filepath.Join(failedDir, fmt.Sprintf("%s.%d", item.Filename, time.Now().UnixNano()))
	}
	err := os.Rename(item.Path, failedPath)
	if err != nil {
		log.Printf("[queue] error quarantining %s to .failed/: %v", item.Filename, err)
	} else {
		if count > 0 {
			log.Printf("[queue] WARN: file %s reached %d failed attempts (%v); quarantined to .failed/%s", item.Filename, count, reason, filepath.Base(failedPath))
		} else {
			log.Printf("[queue] WARN: file %s permanently rejected (%v); quarantined to .failed/%s", item.Filename, reason, filepath.Base(failedPath))
		}
	}

	delete(q.attempts, item.Filename)
	delete(q.inQueue, item.Filename)
	q.updateFailedCount()
}

// RecordFailure increments attempts for the item. If attempts reach maxAttempts,
// the file is quarantined to <dir>/.failed/<filename>. Otherwise, it is requeued.
// Returns true if quarantined, false if requeued for retry.
func (q *Queue) RecordFailure(item FileItem, reason error) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.attempts[item.Filename]++
	count := q.attempts[item.Filename]

	if count >= q.maxAttempts {
		q.quarantineLocked(item, reason, count)
		return true
	}

	// Requeue at the head or sorted order for retry
	if _, exists := q.inQueue[item.Filename]; !exists {
		q.items = append([]FileItem{item}, q.items...)
		q.inQueue[item.Filename] = struct{}{}
		sort.Slice(q.items, func(i, j int) bool {
			return q.items[i].ModTime.Before(q.items[j].ModTime)
		})
		if q.tracker != nil {
			q.tracker.SetQueueCounts(len(q.items), q.failedCount)
		}
		q.cond.Signal()
	}

	return false
}

func (q *Queue) Stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stopped = true
	q.cond.Broadcast()
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
