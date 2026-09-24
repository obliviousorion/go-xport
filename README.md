# xport

A lightweight, zero-dependency point-to-point file transport daemon with mutual TLS 1.3 fingerprint pinning, atomic filesystem commits, and streaming SHA-256 verification.

---

## Build

```bash
go build -o xport ./cmd/xport
```

---

## Two-Device Transfer Guide

### Phase 0: Clean Slate (Run on Both PCs)

Wipe any stale certificates, test directories, or lingering processes to avoid fingerprint mismatches.

```bash
# Kill any running xport instances
pkill -f xport || true

# Remove old keys and transfer directories
rm -rf keys incoming outbox
```

---

### Phase 1: Machine B (Receiver) Setup & Keygen

Run all commands on **Machine B**.

```bash
# 1. Get Machine B's IP address (Save this as RECEIVER_IP)
hostname -I | awk '{print $1}'

# 2. Create directories
mkdir -p incoming keys

# 3. Generate Receiver keypair
./xport keygen -name keys/receiver

# 4. Print Receiver Fingerprint (Save this 64-character hash as RECEIVER_FP)
openssl x509 -in keys/receiver.crt -outform DER | sha256sum | awk '{print $1}'
```

---

### Phase 2: Machine A (Sender) Setup & Keygen

Run all commands on **Machine A**.

```bash
# 1. Create directories
mkdir -p outbox keys

# 2. Generate Sender keypair
./xport keygen -name keys/sender

# 3. Print Sender Fingerprint (Save this 64-character hash as SENDER_FP)
openssl x509 -in keys/sender.crt -outform DER | sha256sum | awk '{print $1}'
```

---

### Phase 3: Start the Daemons

#### 1. On Machine B (Receiver)

Replace `<SENDER_FP>` with the 64-character hash printed from **Machine A**:

```bash
./xport recv \
  -dir ./incoming \
  -listen 0.0.0.0:9000 \
  -cert keys/receiver.crt \
  -key keys/receiver.key \
  -peer-fp "<SENDER_FP>" \
  -name recv-node \
  -status 127.0.0.1:9101
```

*Expected output:*

```text
[receiver] ingress server listening on 0.0.0.0:9000
[receiver] status server listening on 127.0.0.1:9101
```

#### 2. On Machine A (Sender)

Replace `<RECEIVER_IP>` and `<RECEIVER_FP>` with the values from **Machine B**:

```bash
./xport send \
  -dir ./outbox \
  -addr "<RECEIVER_IP>:9000" \
  -cert keys/sender.crt \
  -key keys/sender.key \
  -peer-fp "<RECEIVER_FP>" \
  -parallel 1 \
  -after archive \
  -name send-node \
  -status 127.0.0.1:9100
```

*Expected output:*

```text
[sender] watching ./outbox, dispatching to <RECEIVER_IP>:9000 (parallel=1)
[sender] status server listening on 127.0.0.1:9100
```

---

### Phase 4: Transmit Test Shard & Verify Hash

#### 1. On Machine A (Sender)

Open a **new terminal tab** in the same directory:

```bash
# Create a 20MB random payload under temporary naming
dd if=/dev/urandom of=outbox/.test_shard.tar.tmp bs=1M count=20

# Calculate and display the original SHA-256 hash
sha256sum outbox/.test_shard.tar.tmp | awk '{print $1}' > /tmp/expected.sha256
echo "Expected hash: $(cat /tmp/expected.sha256)"

# Atomically trigger transmission
mv outbox/.test_shard.tar.tmp outbox/test_shard.tar
```

#### 2. Verify on Machine B (Receiver)

Once Machine A shows the file archived to `outbox/.sent/test_shard.tar`, check Machine B:

```bash
sha256sum incoming/test_shard.tar
```

The output hash on Machine B will match the expected hash displayed on Machine A.

---

## CLI Summary

| Command | Primary Flags | Description |
|---|---|---|
| `keygen` | `-name <prefix>`, `-days <int>` | Generate ECDSA P-256 keypair and print SHA-256 fingerprint |
| `recv` | `-dir <path>`, `-listen <addr>`, `-cert <path>`, `-key <path>`, `-peer-fp <fp>` | Run receiver daemon with mTLS and atomic commit |
| `send` | `-dir <path>`, `-addr <addr>`, `-cert <path>`, `-key <path>`, `-peer-fp <fp>`, `-after <archive\|delete>` | Watch directory and stream files to receiver |
| `monitor` | `-targets <addr@fp,...>`, `-cert <path>`, `-key <path>`, `-watch <interval>` | Poll node diagnostics and render terminal dashboard |

---

## Testing & Docker

- **Run test harness:**
  ```bash
  ./test.sh
  ```
- **Run via Docker Compose:**
  ```bash
  docker compose up
  ```
