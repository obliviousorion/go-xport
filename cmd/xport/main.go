package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xport/internal/monitor"
	"xport/internal/receiver"
	"xport/internal/sender"
	"xport/internal/tlsutil"
	"xport/internal/wire"
)

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "node"
	}
	return h
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "keygen":
		runKeygen(args)
	case "send":
		runSend(args)
	case "recv":
		runRecv(args)
	case "monitor":
		runMonitor(args)
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", subcommand)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: xport <subcommand> [flags]

Subcommands:
  keygen   Generate ECDSA P-256 TLS keypair and print SHA-256 fingerprint
  send     Run sender daemon to watch directory and stream files to receiver
  recv     Run receiver daemon to listen for XP1 streams and commit files
  monitor  Run diagnostic monitor dashboard across multiple nodes
`)
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	name := fs.String("name", "node", "Output prefix for <name>.crt and <name>.key")
	days := fs.Int("days", 3650, "Certificate validity period in days")
	_ = fs.Parse(args)

	certFile := fmt.Sprintf("%s.crt", *name)
	keyFile := fmt.Sprintf("%s.key", *name)

	fp, err := tlsutil.GenerateCert(*name, *days, certFile, keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s and %s\n", certFile, keyFile)
	fmt.Printf("Certificate SHA-256 Fingerprint: %s\n", fp)
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	dir := fs.String("dir", "outbox", "Watch directory")
	addr := fs.String("addr", "", "Receiver host:port (required)")
	cert := fs.String("cert", "", "Path to client certificate (required)")
	key := fs.String("key", "", "Path to client private key (required)")
	peerFP := fs.String("peer-fp", "", "Comma-separated list of valid receiver cert SHA-256 fingerprints (required)")
	parallel := fs.Int("parallel", 1, "Number of parallel sender worker connections")
	after := fs.String("after", "archive", "Post-commit action: archive or delete")
	scan := fs.Duration("scan", 1*time.Second, "Polling frequency for directory watcher")
	maxAttempts := fs.Int("max-attempts", 10, "Retries before moving a file to .failed/")
	name := fs.String("name", defaultHostname(), "Node identifier for logs and status reporting")
	statusAddr := fs.String("status", "127.0.0.1:9100", "Bind address for health/metrics HTTP listener")
	statusPeerFP := fs.String("status-peer-fp", "", "Pinned certificate fingerprint of central monitor")
	stallAfter := fs.Duration("stall-after", 2*time.Minute, "Inactivity threshold with pending files before FAIL state")
	diskWarnPct := fs.Int("disk-warn-pct", 15, "Free space warning threshold")
	diskFailPct := fs.Int("disk-fail-pct", 5, "Free space critical failure threshold")
	_ = fs.Parse(args)

	if *addr == "" || *cert == "" || *key == "" || *peerFP == "" {
		fmt.Fprintf(os.Stderr, "error: -addr, -cert, -key, and -peer-fp are required flags for send\n")
		fs.Usage()
		os.Exit(2)
	}

	if err := os.MkdirAll(*dir, 0755); err != nil {
		log.Fatalf("failed to create watch directory %s: %v", *dir, err)
	}

	allowedFPs := tlsutil.ParseFingerprints([]string{*peerFP})
	if len(allowedFPs) == 0 {
		log.Fatalf("no valid peer fingerprints provided in -peer-fp")
	}

	tracker := monitor.NewTracker(*name, monitor.RoleSender, *dir, *diskWarnPct, *diskFailPct, *stallAfter, 0)

	// Status HTTP/TLS server
	statusServer, err := monitor.NewServer(tracker, *statusAddr, *cert, *key, *statusPeerFP)
	if err != nil {
		log.Fatalf("failed to initialize status server: %v", err)
	}
	if err := statusServer.Start(); err != nil {
		log.Fatalf("failed to start status server: %v", err)
	}
	defer statusServer.Close()
	log.Printf("[sender] status server listening on %s", *statusAddr)

	queue := sender.NewQueue(*dir, *maxAttempts, tracker)
	scanner := sender.NewScanner(*dir, *scan, queue)
	pool := sender.NewClientPool(*dir, *addr, *cert, *key, allowedFPs, *parallel, *after, queue, scanner, tracker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanner.Start()
	pool.Start(ctx)
	log.Printf("[sender] watching %s, dispatching to %s (parallel=%d)", *dir, *addr, *parallel)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Printf("[sender] shutting down...")
	scanner.Stop()
	pool.Stop()
	cancel()
	log.Printf("[sender] stopped cleanly")
}

func runRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	dir := fs.String("dir", "incoming", "Target directory for committed files")
	listen := fs.String("listen", ":9000", "TCP bind address for file ingress")
	cert := fs.String("cert", "", "Path to server certificate (required)")
	key := fs.String("key", "", "Path to server private key (required)")
	peerFP := fs.String("peer-fp", "", "Comma-separated list of valid sender cert SHA-256 fingerprints (required)")
	maxSizeStr := fs.String("max-size", "64GiB", "Max payload size allowed per file")
	name := fs.String("name", defaultHostname(), "Node identifier for logs and status reporting")
	statusAddr := fs.String("status", "127.0.0.1:9101", "Bind address for health/metrics HTTP listener")
	statusPeerFP := fs.String("status-peer-fp", "", "Pinned certificate fingerprint of central monitor")
	staleAfter := fs.Duration("stale-after", 0, "Duration without commits before WARN (0 = disabled)")
	diskWarnPct := fs.Int("disk-warn-pct", 15, "Free space warning threshold")
	diskFailPct := fs.Int("disk-fail-pct", 5, "Free space critical failure threshold")
	_ = fs.Parse(args)

	if *cert == "" || *key == "" || *peerFP == "" {
		fmt.Fprintf(os.Stderr, "error: -cert, -key, and -peer-fp are required flags for recv\n")
		fs.Usage()
		os.Exit(2)
	}

	maxSize, err := wire.ParseByteSize(*maxSizeStr)
	if err != nil {
		log.Fatalf("invalid -max-size %q: %v", *maxSizeStr, err)
	}

	if err := os.MkdirAll(*dir, 0755); err != nil {
		log.Fatalf("failed to create incoming directory %s: %v", *dir, err)
	}

	allowedFPs := tlsutil.ParseFingerprints([]string{*peerFP})
	if len(allowedFPs) == 0 {
		log.Fatalf("no valid peer fingerprints provided in -peer-fp")
	}

	tracker := monitor.NewTracker(*name, monitor.RoleReceiver, *dir, *diskWarnPct, *diskFailPct, 0, *staleAfter)

	// Status HTTP/TLS server
	statusServer, err := monitor.NewServer(tracker, *statusAddr, *cert, *key, *statusPeerFP)
	if err != nil {
		log.Fatalf("failed to initialize status server: %v", err)
	}
	if err := statusServer.Start(); err != nil {
		log.Fatalf("failed to start status server: %v", err)
	}
	defer statusServer.Close()
	log.Printf("[receiver] status server listening on %s", *statusAddr)

	recvServer := receiver.NewServer(*dir, *listen, *cert, *key, allowedFPs, maxSize, tracker)
	if err := recvServer.Start(); err != nil {
		log.Fatalf("failed to start receiver ingress server: %v", err)
	}
	defer recvServer.Close()
	log.Printf("[receiver] ingress server listening on %s (commit dir=%s)", *listen, *dir)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Printf("[receiver] shutting down...")
	_ = recvServer.Close()
	log.Printf("[receiver] stopped cleanly")
}

func runMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	targets := fs.String("targets", "", "Comma-separated endpoints formatted as host:port@fingerprint (required)")
	cert := fs.String("cert", "", "Path to monitor client certificate (required)")
	key := fs.String("key", "", "Path to monitor client private key (required)")
	watch := fs.Duration("watch", 10*time.Second, "Continuous poll loop interval (0 for single run)")
	timeout := fs.Duration("timeout", 5*time.Second, "HTTP client timeout per target poll")
	_ = fs.Parse(args)

	if *targets == "" || *cert == "" || *key == "" {
		fmt.Fprintf(os.Stderr, "error: -targets, -cert, and -key are required flags for monitor\n")
		fs.Usage()
		os.Exit(2)
	}

	exitCode := monitor.RunMonitor(*targets, *cert, *key, *watch, *timeout)
	os.Exit(exitCode)
}
