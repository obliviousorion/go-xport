# `xport` — Distributed Systems Transport Daemon & Health Monitor

`xport` is an independent, high-performance, point-to-point data transport daemon and health monitor built for distributed ML training and data ingestion pipelines. Written in **pure Go 1.22+ using only the standard library (zero external dependencies)**, `xport` guarantees bit-for-bit data integrity, atomic durability barriers, and mutual TLS 1.3 certificate fingerprint pinning.

---

## Key Architectural Features

- **Strict Standard Library (Zero Dependencies):** Zero third-party Go modules, reducing supply chain attack surface and binary footprint.
- **XP1 Streaming Protocol:** High-throughput streaming framing over raw TCP wrapped in TLS 1.3, utilizing buffered I/O (`io.CopyBuffer` with a 1 MB transfer buffer) with simultaneous on-the-fly SHA-256 calculation.
- **Fingerprint-Pinned Mutual TLS 1.3:** Traditional PKI CA validation and certificate expiration checks are bypassed in favor of direct raw DER SHA-256 fingerprint allowlists compared using constant-time crypto (`subtle.ConstantTimeCompare`).
- **Filesystem Durability Barrier:** 
  1. Isolated staging inside `.staging/` colocated on the incoming root filesystem (preventing `EXDEV` cross-device link errors).
  2. Byte-count and SHA-256 trailer verification.
  3. `file.Sync()` flushes file content and inode blocks.
  4. Atomic rename into destination directory.
  5. `dir.Sync()` flushes directory inode blocks to physical storage.
  6. Emits `0x00` ACK only after both file and directory blocks are physically committed.
- **Two-Scan Stability Gate:** Outbox polling requires candidate files to retain identical `Size` and `ModTime` across two consecutive scans before dispatch, ensuring half-written producer files are never streamed.
- **FIFO Queue & Poison Quarantine:** Oldest-modification-time-first dispatch (strict sequence when `-parallel 1`). Files failing 10 times (`-max-attempts`) are moved to `.failed/` to prevent head-of-line blocking.
- **Persistent TLS Worker Connections:** Workers maintain long-lived TLS connections across multiple files without per-file reconnection overhead.
- **Internal Health State Machine & Metrics:**
  - Evaluates node state: `OK`, `WARN`, `FAIL`.
  - Zero-dependency Linux disk space calculation using `syscall.Statfs` (`stat.Bavail`).
  - Diagnostic endpoints: `GET /status` (JSON), `GET /healthz` (200/503), and `GET /metrics` (Prometheus exposition format).
  - Mutual TLS enforcement on off-box non-loopback health listeners.
- **Central CLI Monitor:** Polls distributed nodes concurrently and renders a terminal dashboard with standard UNIX exit codes (`0`=OK, `1`=WARN, `2`=FAIL/DOWN).

---

## Project Layout

```text
xport/
├── cmd/
│   └── xport/
│       └── main.go              # CLI router: keygen, send, recv, monitor
├── internal/
│   ├── wire/                    # XP1 wire protocol framing & serialization
│   │   ├── protocol.go          # Magic bytes, header framing, stream copy + SHA-256
│   │   └── protocol_test.go     # Round-trip, corrupt checksum, length mismatch unit tests
│   ├── tlsutil/                 # TLS 1.3 & public key fingerprint pinning
│   │   ├── certs.go             # ECDSA P-256 keygen & self-signed X.509 cert creation
│   │   ├── verify.go            # VerifyPeerCertificate callback using SHA-256 DER fingerprints
│   │   └── tlsutil_test.go      # Pin matching, rejection of unpinned certs, constant-time compare
│   ├── sender/                  # Sender engine
│   │   ├── scanner.go           # Directory poller, 2-scan stability gate (size + modtime)
│   │   ├── queue.go             # In-memory FIFO queue, retry counter & .failed/ quarantine
│   │   ├── client.go            # Persistent TLS workers, XP1 streamer, archive/delete policies
│   │   └── sender_test.go       # Stability gate, FIFO ordering & quarantine tests
│   ├── receiver/                # Receiver engine
│   │   ├── listener.go          # TLS 1.3 listener & active connection dispatcher
│   │   ├── stager.go            # Isolated staging stream writer (.staging/) & boot cleaner
│   │   ├── committer.go         # Durability barrier: fsync(file) -> rename -> fsync(dir) -> ACK
│   │   └── receiver_test.go     # Staging cleanup, atomic commit, and durability barrier tests
│   └── monitor/                 # Observability & diagnostic health system
│       ├── status.go            # Health state machine (OK, WARN, FAIL), syscall.Statfs disk stats
│       ├── server.go            # Endpoints: /status (JSON), /healthz (200/503), /metrics (Prometheus)
│       ├── client.go            # Cluster poll engine & terminal tabular dashboard
│       └── monitor_test.go      # State transitions, metrics serialization, and exit code tests
├── go.mod                       # Pure Go standard library (Go 1.22+)
├── Dockerfile                   # Multi-stage lightweight Alpine build
├── docker-compose.yml           # Pinned sender-receiver-monitor topology
└── test.sh                      # Automated 8-suite verification harness
```

---

## Wire Protocol (`XP1`)

```
SENDER                                                     RECEIVER
  │                                                           │
  │─── Magic: "XP1\n" (4B) ──────────────────────────────────>│
  │─── Name Length: uint16 Big-Endian (2B) ──────────────────>│
  │─── Filename: UTF-8 string (L Bytes) ─────────────────────>│
  │─── Payload Size: uint64 Big-Endian (8B) ─────────────────>│
  │─── Raw Payload: Streamed Data (N Bytes) ─────────────────>│ (Written to .staging/<rand>.tmp)
  │─── Hash Trailer: SHA-256 Checksum (32B) ─────────────────>│ (Computed on the fly)
  │                                                           │ [fsync file -> rename -> fsync dir]
  │<── Reply: 0x00 (Success) OR 0x01 + u16 len + msg (Error) ─│
```

- **Magic Header:** 4 bytes ASCII `XP1\n` (`0x58, 0x50, 0x31, 0x0A`).
- **Filename Validation:** Basename only (path separators `/` and `\` strictly rejected), matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`, must not end in `.tmp` or `.part`.
- **Payload Streaming:** Streamed with a 1 MB buffer (`io.CopyBuffer`), piping simultaneously into `crypto/sha256`.
- **Durability ACK:** Single byte `0x00` transmitted only after `file.Sync()`, `os.Rename()`, and `dir.Sync()` have completed.
- **NACK Frame:** Single byte `0x01` + 2-byte Big-Endian length + UTF-8 human-readable error description.

---

## Connection Deadlines

`xport` enforces strict deadlines on all socket connections:
- **TLS Handshake Deadline:** 10s (`wire.HandshakeTimeout`).
- **Read/Write Stall Deadline:** 60s (`wire.ReadWriteTimeout`).
- **Receiver Idle Timeout:** 2m (`wire.ReceiverIdleTimeout`) waiting for subsequent files on persistent connections.

---

## CLI Reference & Flags

### 1. Key Generation (`xport keygen`)
Generates an ECDSA P-256 private key and self-signed X.509 certificate, printing its SHA-256 fingerprint:
```bash
xport keygen -name node -days 3650
```
- `-name` *(string, default: "node")*: Output prefix for `<name>.crt` and `<name>.key`.
- `-days` *(int, default: 3650)*: Certificate validity duration.

### 2. File Receiver (`xport recv`)
Listens for incoming XP1 streams, validates fingerprints, commits files atomically, and serves diagnostics:
```bash
xport recv -dir /data/incoming -listen 0.0.0.0:9000 \
  -cert receiver.crt -key receiver.key \
  -peer-fp <SENDER_FP> -name recv-A \
  -status 127.0.0.1:9101
```
- `-dir` *(string, default: "incoming")*: Target directory for committed files.
- `-listen` *(string, default: ":9000")*: TCP bind address for file ingress.
- `-cert` *(string, required)*: Path to server certificate.
- `-key` *(string, required)*: Path to server private key.
- `-peer-fp` *(string, required)*: Comma-separated allowlist of valid sender SHA-256 fingerprints.
- `-max-size` *(string, default: "64GiB")*: Maximum payload size per file (e.g. `500MB`, `64GiB`).
- `-name` *(string, default: hostname)*: Node identifier for logs and status reporting.
- `-status` *(string, default: "127.0.0.1:9101")*: Bind address for health/metrics HTTP listener.
- `-status-peer-fp` *(string, default: "")*: Pinned certificate fingerprint of central monitor (required if `-status` is non-loopback).
- `-stale-after` *(duration, default: 0)*: Inactivity duration without commits before signaling `WARN`.
- `-disk-warn-pct` *(int, default: 15)*: Free space warning threshold percentage.
- `-disk-fail-pct` *(int, default: 5)*: Free space critical failure threshold percentage.

### 3. File Sender (`xport send`)
Polls directory with a 2-scan stability check, streams files over persistent TLS connections, and executes post-commit policies:
```bash
xport send -dir /data/outbox -addr 10.0.1.50:9000 \
  -cert sender.crt -key sender.key \
  -peer-fp <RECEIVER_FP> -parallel 1 -after archive \
  -name send-A -status 127.0.0.1:9100
```
- `-dir` *(string, default: "outbox")*: Watch directory.
- `-addr` *(string, required)*: Receiver address (`host:port`).
- `-cert` *(string, required)*: Path to client certificate.
- `-key` *(string, required)*: Path to client private key.
- `-peer-fp` *(string, required)*: Comma-separated allowlist of valid receiver SHA-256 fingerprints.
- `-parallel` *(int, default: 1)*: Number of parallel sender worker connections.
- `-after` *(string, default: "archive")*: Post-commit policy (`archive` moves to `.sent/`, `delete` calls `os.Remove`).
- `-scan` *(duration, default: 1s)*: Polling frequency for directory watcher.
- `-max-attempts` *(int, default: 10)*: Retry limit before parking a poisoned file into `<dir>/.failed/`.
- `-stall-after` *(duration, default: 2m)*: Inactivity threshold with pending files before signaling `FAIL`.
- `-name` *(string, default: hostname)*: Node identifier for logs and status reporting.
- `-status` *(string, default: "127.0.0.1:9100")*: Bind address for health/metrics HTTP listener.
- `-status-peer-fp` *(string, default: "")*: Pinned certificate fingerprint of central monitor.
- `-disk-warn-pct` *(int, default: 15)*: Free space warning threshold percentage.
- `-disk-fail-pct` *(int, default: 5)*: Free space critical failure threshold percentage.

### 4. Central Monitor (`xport monitor`)
Polls cluster nodes concurrently via pinned mutual TLS, rendering a terminal dashboard:
```bash
xport monitor -cert monitor.crt -key monitor.key -watch 10s \
  -targets 10.0.1.25:9100@<SENDER_FP>,10.0.1.50:9101@<RECEIVER_FP>
```
Output:
```text
NODE     ROLE      STATE  FILES  DATA     ERR  WAITING  FAILED  LAST-OK  DISK-FREE  ISSUES
send-A   sender    OK     12     100.0MB  0    0        0       2s       92%        
recv-A   receiver  OK     12     100.0MB  0    0        0       2s       92%        
```
**Exit Codes:**
- `0`: All target nodes are in state `OK`.
- `1`: Any target node is in state `WARN` (and none `FAIL` or unreachable).
- `2`: Any target node is in state `FAIL` or unreachable (`DOWN`).

---

## Health State Machine Rules

| State | Sender Conditions | Receiver Conditions |
|---|---|---|
| **FAIL** | Files pending in queue AND no successful transfer for $> \text{stall-after}$. Storage free space falls below `-disk-fail-pct`. | Storage free space falls below `-disk-fail-pct`. |
| **WARN** | Files parked in `.failed/`. Any error within the last 5 minutes. Storage free space below `-disk-warn-pct`. | Any handshake refusal or rejected file in the last 5 minutes. A staging file untouched for 10+ minutes with no active connection. No commits for $> \text{stale-after}$. Storage free space below `-disk-warn-pct`. |
| **OK** | Normal operation, queue processing cleanly, disk healthy. | Normal operation, files committing cleanly, disk healthy. |

---

## Verification Test Harness (`test.sh`)

An end-to-end automated validation suite is provided in `test.sh`. It automatically builds the binary and executes 8 comprehensive verification test suites:

```bash
chmod +x test.sh
./test.sh
```

### Verification Matrix
1. **Key Generation & Fingerprint Extraction:** Generates sender, receiver, monitor, and rogue ECDSA P-256 keypairs and extracts fingerprints.
2. **Bit-for-Bit Hash Integrity Check:** Streams 100 MB of pseudorandom data (`dd if=/dev/urandom`) and asserts SHA-256 equality between outbox archive and committed incoming file.
3. **Deterministic Sequence Validation:** Drops 10 sequential shards (`seq_shard_00001.tar` to `seq_shard_00010.tar`) and verifies arrival and commit order strictly matches numerical sequence.
4. **Security Pin Refusal:** Probes receiver ingress with an unpinned certificate and plaintext HTTP; asserts immediate rejection and zero bytes staged.
5. **Poison File Quarantine:** Streams a 10 KB file against a 500 B receiver limit; asserts that after 10 failed attempts the poison file is parked in `.failed/` while subsequent valid files process without head-of-line blocking.
6. **Central Monitoring Assertions:** Validates exit codes `0` (clean cluster), `1` (quarantined file WARN), and `2` (downed receiver node).
7. **Mid-Stream SIGKILL Injection & Boot Cleanup:** Streams a 50 MB file and injects `kill -9` on the receiver mid-stream. Verifies boot cleanup wipes partial `.staging/` content, sender reconnects, and the complete file is committed with 0 corruption.
8. **Diagnostic Endpoints:** Validates `/status` JSON response, `/healthz` (200 OK / 503 FAIL), and `/metrics` (Prometheus text format).

---

## Docker & Docker Compose

Build image:
```bash
docker build -t xport:latest .
```

Run cluster via Docker Compose:
```bash
# Set fingerprints in environment
export SENDER_FP="..."
export RECEIVER_FP="..."
export MONITOR_FP="..."

docker compose up
```
