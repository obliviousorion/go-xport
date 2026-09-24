package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiskStats(t *testing.T) {
	tempDir := t.TempDir()
	stats, err := GetDiskStats(tempDir)
	if err != nil {
		t.Fatalf("GetDiskStats failed: %v", err)
	}
	if stats.TotalBytes == 0 {
		t.Errorf("expected non-zero total bytes")
	}
	if stats.FreePercent < 0 || stats.FreePercent > 100 {
		t.Errorf("invalid free percent: %d", stats.FreePercent)
	}
}

func TestSenderStateEvaluation(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Initial healthy state (disable disk thresholds for hermetic testing)
	tracker := NewTracker("send-test", RoleSender, tempDir, 15, 5, 2*time.Second, 0)
	tracker.mu.Lock()
	tracker.diskWarnPct = 0
	tracker.diskFailPct = 0
	tracker.mu.Unlock()

	st := tracker.Evaluate()
	if st.State != StateOK {
		t.Fatalf("expected state OK, got %s", st.State)
	}

	// 2. Add error -> WARN
	tracker.RecordError()
	st = tracker.Evaluate()
	if st.State != StateWarn {
		t.Fatalf("expected state WARN on recent error, got %s", st.State)
	}

	// 3. Parked files in .failed -> WARN
	tracker.SetQueueCounts(0, 1)
	st = tracker.Evaluate()
	if st.State != StateWarn {
		t.Fatalf("expected state WARN on failed files, got %s", st.State)
	}

	// 4. Pending files + stall-after exceeded -> FAIL
	tracker.SetQueueCounts(2, 0)
	time.Sleep(2100 * time.Millisecond) // exceeds 2s stallAfter
	st = tracker.Evaluate()
	if st.State != StateFail {
		t.Fatalf("expected state FAIL when stalled with waiting files, got %s", st.State)
	}

	// 5. Verify idle period without waiting files does not trigger false FAIL
	tracker.SetQueueCounts(0, 0)
	tracker.RecordSuccess(1024)
	time.Sleep(2100 * time.Millisecond) // exceeds 2s stallAfter
	// Now a file is queued
	tracker.SetQueueCounts(1, 0)
	st = tracker.Evaluate()
	if st.State == StateFail {
		t.Fatalf("expected state not to be FAIL immediately after enqueuing file, got %s", st.State)
	}
}

func TestServerEndpoints(t *testing.T) {
	tempDir := t.TempDir()
	tracker := NewTracker("node-1", RoleSender, tempDir, 15, 5, 10*time.Minute, 0)
	tracker.RecordSuccess(1024)

	server, err := NewServer(tracker, "127.0.0.1:0", "", "", "")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Test GET /status
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	server.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/status returned %d", w.Code)
	}
	var st NodeStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("failed to decode /status: %v", err)
	}
	if st.NodeID != "node-1" || st.FilesTotal != 1 {
		t.Fatalf("unexpected status values: %+v", st)
	}

	// Test GET /healthz when OK
	w = httptest.NewRecorder()
	server.handleHealthz(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/healthz returned %d, expected 200", w.Code)
	}

	// Test GET /healthz when FAIL
	tracker.mu.Lock()
	tracker.diskFailPct = 100 // Force fail
	tracker.mu.Unlock()

	w = httptest.NewRecorder()
	server.handleHealthz(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz returned %d, expected 503", w.Code)
	}

	// Test GET /metrics
	w = httptest.NewRecorder()
	server.handleMetrics(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "xport_state{node=\"node-1\",role=\"sender\"} 2") {
		t.Fatalf("expected state metric 2 in metrics output, got:\n%s", body)
	}
}

func TestEvaluateExitCode(t *testing.T) {
	okResult := PollResult{Status: &NodeStatus{State: StateOK}}
	warnResult := PollResult{Status: &NodeStatus{State: StateWarn}}
	failResult := PollResult{Status: &NodeStatus{State: StateFail}}
	errResult := PollResult{Error: http.ErrHandlerTimeout}

	if code := EvaluateExitCode([]PollResult{okResult, okResult}); code != 0 {
		t.Errorf("expected 0 for all OK, got %d", code)
	}
	if code := EvaluateExitCode([]PollResult{okResult, warnResult}); code != 1 {
		t.Errorf("expected 1 for OK + WARN, got %d", code)
	}
	if code := EvaluateExitCode([]PollResult{okResult, failResult}); code != 2 {
		t.Errorf("expected 2 for OK + FAIL, got %d", code)
	}
	if code := EvaluateExitCode([]PollResult{okResult, errResult}); code != 2 {
		t.Errorf("expected 2 for OK + DOWN, got %d", code)
	}
}

func TestParseTargets(t *testing.T) {
	raw := "10.0.1.25:9100@abcdef1234567890, 127.0.0.1:9101"
	targets, err := ParseTargets(raw)
	if err != nil {
		t.Fatalf("ParseTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].Address != "10.0.1.25:9100" || targets[0].Fingerprint != "abcdef1234567890" {
		t.Errorf("unexpected target 0: %+v", targets[0])
	}
	if targets[1].Address != "127.0.0.1:9101" || targets[1].Fingerprint != "" {
		t.Errorf("unexpected target 1: %+v", targets[1])
	}
}
