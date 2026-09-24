package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"xport/internal/tlsutil"
)

type Target struct {
	Address     string
	Fingerprint string
}

type PollResult struct {
	Target Target
	Status *NodeStatus
	Error  error
}

func ParseTargets(raw string) ([]Target, error) {
	var targets []Target
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		atIdx := strings.Index(p, "@")
		if atIdx == -1 {
			// Plain address without fingerprint (assumed loopback plain HTTP)
			targets = append(targets, Target{Address: p, Fingerprint: ""})
		} else {
			addr := p[:atIdx]
			fp := tlsutil.NormalizeFingerprint(p[atIdx+1:])
			targets = append(targets, Target{Address: addr, Fingerprint: fp})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets specified")
	}
	return targets, nil
}

func PollTarget(ctx context.Context, target Target, certFile, keyFile string, timeout time.Duration) PollResult {
	scheme := "https"
	if target.Fingerprint == "" {
		scheme = "http"
	}

	url := fmt.Sprintf("%s://%s/status", scheme, target.Address)

	var transport *http.Transport
	if scheme == "https" {
		tlsCfg, err := tlsutil.NewClientTLSConfig(certFile, keyFile, []string{target.Fingerprint})
		if err != nil {
			return PollResult{Target: target, Error: fmt.Errorf("client tls error: %w", err)}
		}
		transport = &http.Transport{
			TLSClientConfig: tlsCfg,
		}
	} else {
		transport = &http.Transport{}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PollResult{Target: target, Error: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return PollResult{Target: target, Error: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return PollResult{Target: target, Error: fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}

	var st NodeStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return PollResult{Target: target, Error: fmt.Errorf("failed to parse status json: %w", err)}
	}

	return PollResult{Target: target, Status: &st}
}

func PollAll(ctx context.Context, targets []Target, certFile, keyFile string, timeout time.Duration) []PollResult {
	results := make([]PollResult, len(targets))
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target Target) {
			defer wg.Done()
			results[idx] = PollTarget(ctx, target, certFile, keyFile, timeout)
		}(i, t)
	}

	wg.Wait()
	return results
}

func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func RenderTable(results []PollResult) {
	fmt.Printf("%-8s %-9s %-6s %-6s %-8s %-4s %-8s %-7s %-8s %-10s %s\n",
		"NODE", "ROLE", "STATE", "FILES", "DATA", "ERR", "WAITING", "FAILED", "LAST-OK", "DISK-FREE", "ISSUES")

	for _, res := range results {
		if res.Error != nil {
			nodeName := res.Target.Address
			fmt.Printf("%-8s %-9s %-6s %-6s %-8s %-4s %-8s %-7s %-8s %-10s %s\n",
				nodeName, "-", "DOWN", "-", "-", "-", "-", "-", "-", "-", res.Error.Error())
			continue
		}

		st := res.Status
		issuesStr := strings.Join(st.ActiveIssues, "; ")
		lastOk := fmt.Sprintf("%ds", st.LastOkSeconds)
		diskFree := fmt.Sprintf("%d%%", st.Disk.FreePercent)
		stateUpper := strings.ToUpper(string(st.State))

		fmt.Printf("%-8s %-9s %-6s %-6d %-8s %-4d %-8d %-7d %-8s %-10s %s\n",
			st.NodeID,
			st.Role,
			stateUpper,
			st.FilesTotal,
			FormatBytes(st.BytesTotal),
			st.ErrorsTotal,
			st.WaitingFiles,
			st.FailedFiles,
			lastOk,
			diskFree,
			issuesStr,
		)
	}
}

// EvaluateExitCode determines the process exit code:
// 0 = all nodes OK
// 1 = any node WARN (and no node FAIL/DOWN)
// 2 = any node FAIL or DOWN
func EvaluateExitCode(results []PollResult) int {
	hasWarn := false
	for _, res := range results {
		if res.Error != nil {
			return 2
		}
		if res.Status.State == StateFail {
			return 2
		}
		if res.Status.State == StateWarn {
			hasWarn = true
		}
	}
	if hasWarn {
		return 1
	}
	return 0
}

// RunMonitor executes the monitor CLI command.
func RunMonitor(targetsRaw, certFile, keyFile string, watch, timeout time.Duration) int {
	targets, err := ParseTargets(targetsRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing targets: %v\n", err)
		return 2
	}

	if watch <= 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
		defer cancel()
		results := PollAll(ctx, targets, certFile, keyFile, timeout)
		RenderTable(results)
		return EvaluateExitCode(results)
	}

	ticker := time.NewTicker(watch)
	defer ticker.Stop()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
		results := PollAll(ctx, targets, certFile, keyFile, timeout)
		cancel()

		// ANSI clear screen
		fmt.Print("\033[H\033[2J")
		RenderTable(results)

		<-ticker.C
	}
}
