package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type HealthState string

const (
	StateOK   HealthState = "ok"
	StateWarn HealthState = "warn"
	StateFail HealthState = "fail"
)

type Role string

const (
	RoleSender   Role = "sender"
	RoleReceiver Role = "receiver"
)

// DiskStats represents filesystem capacity metrics.
type DiskStats struct {
	TotalBytes   uint64 `json:"total_bytes"`
	FreeBytes    uint64 `json:"free_bytes"`
	FreePercent  int    `json:"free_percent"`
}

// GetDiskStats uses standard library syscall.Statfs (stat.Bavail) for zero-dependency Linux disk calculation.
func GetDiskStats(path string) (DiskStats, error) {
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

// NodeStatus is the JSON structure served at /status.
type NodeStatus struct {
	NodeID          string      `json:"node_id"`
	Role            Role        `json:"role"`
	State           HealthState `json:"state"`
	ActiveIssues    []string    `json:"active_issues"`
	UptimeSeconds   int64       `json:"uptime_seconds"`
	FilesTotal      uint64      `json:"files_total"`
	BytesTotal      uint64      `json:"bytes_total"`
	ErrorsTotal     uint64      `json:"errors_total"`
	WaitingFiles    int         `json:"waiting_files"`
	FailedFiles     int         `json:"failed_files"`
	LastOkSeconds   int64       `json:"last_ok_seconds"`
	Disk            DiskStats   `json:"disk"`
}

// Tracker coordinates state tracking and evaluation for a node.
type Tracker struct {
	mu sync.RWMutex

	nodeID      string
	role        Role
	watchDir    string
	startTime   time.Time

	// Thresholds
	diskWarnPct int
	diskFailPct int
	stallAfter  time.Duration
	staleAfter  time.Duration

	// Metrics
	filesTotal   uint64
	bytesTotal   uint64
	errorsTotal  uint64
	lastOkTime   time.Time
	recentErrors []time.Time // timestamps of recent errors within 5 minutes

	// Sender specific
	waitingFiles   int
	failedFiles    int
	stallStartTime time.Time

	// Receiver specific
	activeConnections int
}

func NewTracker(nodeID string, role Role, watchDir string, diskWarnPct, diskFailPct int, stallAfter, staleAfter time.Duration) *Tracker {
	if diskWarnPct <= 0 {
		diskWarnPct = 15
	}
	if diskFailPct <= 0 {
		diskFailPct = 5
	}

	return &Tracker{
		nodeID:      nodeID,
		role:        role,
		watchDir:    watchDir,
		startTime:   time.Now(),
		diskWarnPct: diskWarnPct,
		diskFailPct: diskFailPct,
		stallAfter:  stallAfter,
		staleAfter:  staleAfter,
		lastOkTime:  time.Now(),
	}
}

func (t *Tracker) RecordSuccess(bytes uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.filesTotal++
	t.bytesTotal += bytes
	t.lastOkTime = time.Now()
	if t.waitingFiles > 0 {
		t.stallStartTime = time.Now()
	} else {
		t.stallStartTime = time.Time{}
	}
}

func (t *Tracker) RecordError() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errorsTotal++
	t.recentErrors = append(t.recentErrors, time.Now())
}

func (t *Tracker) SetQueueCounts(waiting, failed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if waiting > 0 && t.stallStartTime.IsZero() {
		t.stallStartTime = time.Now()
	} else if waiting == 0 {
		t.stallStartTime = time.Time{}
	}
	t.waitingFiles = waiting
	t.failedFiles = failed
}

func (t *Tracker) SetActiveConnections(count int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.activeConnections = count
}

// CleanOldErrors purges error timestamps older than 5 minutes.
func (t *Tracker) pruneErrors(cutoff time.Time) int {
	var active []time.Time
	for _, ts := range t.recentErrors {
		if ts.After(cutoff) {
			active = append(active, ts)
		}
	}
	t.recentErrors = active
	return len(active)
}

// checkOldStagingFiles inspects .staging/ for files untouched for 10+ minutes.
func (t *Tracker) checkOldStagingFiles() bool {
	stagingDir := filepath.Join(t.watchDir, ".staging")
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return false
	}
	tenMinsAgo := time.Now().Add(-10 * time.Minute)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tmp") {
			info, err := entry.Info()
			if err == nil && info.ModTime().Before(tenMinsAgo) {
				return true
			}
		}
	}
	return false
}

// Evaluate computes the current state and returns the complete NodeStatus.
func (t *Tracker) Evaluate() NodeStatus {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff5m := now.Add(-5 * time.Minute)
	recentErrCount := t.pruneErrors(cutoff5m)

	disk, _ := GetDiskStats(t.watchDir)

	state := StateOK
	var issues []string

	// Common disk checks
	if disk.TotalBytes > 0 {
		if t.diskFailPct > 0 && disk.FreePercent < t.diskFailPct {
			state = StateFail
			issues = append(issues, fmt.Sprintf("disk free (%d%%) below critical failure threshold (%d%%)", disk.FreePercent, t.diskFailPct))
		} else if t.diskWarnPct > 0 && disk.FreePercent < t.diskWarnPct {
			if state != StateFail {
				state = StateWarn
			}
			issues = append(issues, fmt.Sprintf("disk free (%d%%) below warning threshold (%d%%)", disk.FreePercent, t.diskWarnPct))
		}
	}

	if t.role == RoleSender {
		// Sender FAIL: Files pending in queue AND no progress for > stall-after duration.
		if t.waitingFiles > 0 && t.stallAfter > 0 && !t.stallStartTime.IsZero() {
			stallDuration := now.Sub(t.stallStartTime)
			if stallDuration > t.stallAfter {
				state = StateFail
				issues = append(issues, fmt.Sprintf("stalled: %d files waiting and no progress for %v (limit: %v)", t.waitingFiles, stallDuration.Round(time.Second), t.stallAfter))
			}
		}

		// Sender WARN:
		// - Files parked in .failed/
		// - Any network or disk error within the last 5 minutes
		if t.failedFiles > 0 {
			if state != StateFail {
				state = StateWarn
			}
			issues = append(issues, fmt.Sprintf("%d file(s) parked in .failed", t.failedFiles))
		}
		if recentErrCount > 0 {
			if state != StateFail {
				state = StateWarn
			}
			issues = append(issues, fmt.Sprintf("%d error(s) occurred in the last 5 minutes", recentErrCount))
		}

	} else if t.role == RoleReceiver {
		// Receiver WARN:
		// - Any handshake refusal or rejected file in the last 5 minutes
		// - A staging file untouched for 10+ minutes with no active connection
		// - No commits for > stale-after (if enabled)
		if recentErrCount > 0 {
			if state != StateFail {
				state = StateWarn
			}
			issues = append(issues, fmt.Sprintf("%d handshake refusal(s) or rejected file(s) in the last 5 minutes", recentErrCount))
		}

		if t.activeConnections == 0 && t.checkOldStagingFiles() {
			if state != StateFail {
				state = StateWarn
			}
			issues = append(issues, "staging file untouched for 10+ minutes with no active connection")
		}

		if t.staleAfter > 0 {
			timeSinceOk := now.Sub(t.lastOkTime)
			if timeSinceOk > t.staleAfter {
				if state != StateFail {
					state = StateWarn
				}
				issues = append(issues, fmt.Sprintf("no commits for %v (stale-after: %v)", timeSinceOk.Round(time.Second), t.staleAfter))
			}
		}
	}

	lastOkSec := int64(now.Sub(t.lastOkTime).Seconds())
	if lastOkSec < 0 {
		lastOkSec = 0
	}

	return NodeStatus{
		NodeID:        t.nodeID,
		Role:          t.role,
		State:         state,
		ActiveIssues:  issues,
		UptimeSeconds: int64(now.Sub(t.startTime).Seconds()),
		FilesTotal:    t.filesTotal,
		BytesTotal:    t.bytesTotal,
		ErrorsTotal:   t.errorsTotal,
		WaitingFiles:  t.waitingFiles,
		FailedFiles:   t.failedFiles,
		LastOkSeconds: lastOkSec,
		Disk:          disk,
	}
}
