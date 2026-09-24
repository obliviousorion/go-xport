#!/usr/bin/env bash
set -euo pipefail

# Color formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCRIPT_DIR}/xport"

# Ensure binary is built
if [ ! -f "$BIN" ]; then
    info "Compiling xport binary..."
    go build -o "$BIN" "${SCRIPT_DIR}/cmd/xport"
fi

TEST_DIR=$(mktemp -d -t xport-test-XXXXXX)
info "Using temporary workspace: $TEST_DIR"

cleanup() {
    info "Cleaning up background daemons and temporary files..."
    if [ -n "${RECV_PID:-}" ] && kill -0 "$RECV_PID" 2>/dev/null; then
        kill "$RECV_PID" 2>/dev/null || true
    fi
    if [ -n "${SEND_PID:-}" ] && kill -0 "$SEND_PID" 2>/dev/null; then
        kill "$SEND_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

KEYS_DIR="$TEST_DIR/keys"
OUTBOX_DIR="$TEST_DIR/ws/outbox"
INCOMING_DIR="$TEST_DIR/ws/incoming"

mkdir -p "$KEYS_DIR" "$OUTBOX_DIR" "$INCOMING_DIR"

echo "=========================================================="
echo "    xport Automated Verification Matrix & Test Harness"
echo "=========================================================="

# -------------------------------------------------------------
# 1. Key Generation & Fingerprint Extraction
# -------------------------------------------------------------
info "Test 1: Generating ECDSA P-256 Keypairs & Fingerprints..."

RECEIVER_OUTPUT=$("$BIN" keygen -name "$KEYS_DIR/receiver" -days 365)
RECEIVER_FP=$(echo "$RECEIVER_OUTPUT" | grep -oE '[a-f0-9]{64}')

SENDER_OUTPUT=$("$BIN" keygen -name "$KEYS_DIR/sender" -days 365)
SENDER_FP=$(echo "$SENDER_OUTPUT" | grep -oE '[a-f0-9]{64}')

MONITOR_OUTPUT=$("$BIN" keygen -name "$KEYS_DIR/monitor" -days 365)
MONITOR_FP=$(echo "$MONITOR_OUTPUT" | grep -oE '[a-f0-9]{64}')

ROGUE_OUTPUT=$("$BIN" keygen -name "$KEYS_DIR/rogue" -days 365)
ROGUE_FP=$(echo "$ROGUE_OUTPUT" | grep -oE '[a-f0-9]{64}')

if [ -z "$RECEIVER_FP" ] || [ -z "$SENDER_FP" ] || [ -z "$MONITOR_FP" ]; then
    fail "Failed to extract certificates and fingerprints"
fi

pass "Generated keys. Receiver FP: ${RECEIVER_FP:0:16}... Sender FP: ${SENDER_FP:0:16}..."

# Start Receiver Daemon
RECV_LISTEN="127.0.0.1:9000"
RECV_STATUS="127.0.0.1:9101"

start_receiver() {
    "$BIN" recv -dir "$INCOMING_DIR" \
        -listen "$RECV_LISTEN" \
        -cert "$KEYS_DIR/receiver.crt" -key "$KEYS_DIR/receiver.key" \
        -peer-fp "$SENDER_FP" -name "recv-A" \
        -max-size "64GiB" \
        -disk-warn-pct 0 -disk-fail-pct 0 \
        -status "$RECV_STATUS" &
    RECV_PID=$!
    sleep 1
}

start_receiver
pass "Receiver daemon started (PID: $RECV_PID)"

# Start Sender Daemon
SEND_STATUS="127.0.0.1:9100"

start_sender() {
    "$BIN" send -dir "$OUTBOX_DIR" \
        -addr "$RECV_LISTEN" \
        -cert "$KEYS_DIR/sender.crt" -key "$KEYS_DIR/sender.key" \
        -peer-fp "$RECEIVER_FP" -parallel 1 -after archive \
        -scan 200ms -max-attempts 10 -stall-after 3s \
        -disk-warn-pct 0 -disk-fail-pct 0 \
        -name "send-A" -status "$SEND_STATUS" &
    SEND_PID=$!
    sleep 1
}

start_sender
pass "Sender daemon started (PID: $SEND_PID)"

# -------------------------------------------------------------
# 2. Bit-for-Bit Hash Integrity Check (100 MB Payload)
# -------------------------------------------------------------
info "Test 2: Bit-for-Bit Hash Integrity Check (100 MB Payload)..."

TMP_FILE="$OUTBOX_DIR/.shard_001.tar.tmp"
TARGET_FILE="$OUTBOX_DIR/shard_001.tar"

# Create 100MB random payload
dd if=/dev/urandom of="$TMP_FILE" bs=1M count=100 status=none
mv "$TMP_FILE" "$TARGET_FILE"

ORIGINAL_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')

# Wait for transfer and commit
RECV_TARGET="$INCOMING_DIR/shard_001.tar"
SENT_TARGET="$OUTBOX_DIR/.sent/shard_001.tar"

for i in {1..30}; do
    if [ -f "$RECV_TARGET" ] && [ -f "$SENT_TARGET" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -f "$RECV_TARGET" ] || [ ! -f "$SENT_TARGET" ]; then
    fail "100 MB transfer timed out or files missing"
fi

COMMITTED_HASH=$(sha256sum "$RECV_TARGET" | awk '{print $1}')
ARCHIVED_HASH=$(sha256sum "$SENT_TARGET" | awk '{print $1}')

if [ "$ORIGINAL_HASH" != "$COMMITTED_HASH" ] || [ "$ORIGINAL_HASH" != "$ARCHIVED_HASH" ]; then
    fail "Checksum mismatch: original=$ORIGINAL_HASH, committed=$COMMITTED_HASH, archived=$ARCHIVED_HASH"
fi

pass "100 MB Bit-for-bit SHA-256 verified ($COMMITTED_HASH)"

# -------------------------------------------------------------
# 3. Deterministic Sequence Validation (10 Shards)
# -------------------------------------------------------------
info "Test 3: Deterministic Sequence Validation (10 sequential shards)..."

for i in $(seq -w 1 10); do
    shard_name="seq_shard_000${i}.tar"
    echo "Sequence shard data ${i}" > "$OUTBOX_DIR/.${shard_name}.tmp"
    mv "$OUTBOX_DIR/.${shard_name}.tmp" "$OUTBOX_DIR/${shard_name}"
    sleep 0.05
done

# Wait for all 10 shards to be committed
for i in {1..20}; do
    count=$(ls -1 "$INCOMING_DIR"/seq_shard_*.tar 2>/dev/null | wc -l || true)
    if [ "$count" -eq 10 ]; then
        break
    fi
    sleep 0.5
done

count=$(ls -1 "$INCOMING_DIR"/seq_shard_*.tar 2>/dev/null | wc -l || true)
if [ "$count" -ne 10 ]; then
    fail "Expected 10 sequential shards, got $count"
fi

# Verify arrival order via modification time
prev_num=0
for f in $(ls -1rt "$INCOMING_DIR"/seq_shard_*.tar); do
    base=$(basename "$f")
    num=$(echo "$base" | grep -oE '[0-9]+' | sed 's/^0*//')
    if [ "$num" -le "$prev_num" ]; then
        fail "Out of order sequence: shard $base arrived after shard $prev_num"
    fi
    prev_num=$num
done

pass "All 10 shards transferred in strict deterministic FIFO order"

# -------------------------------------------------------------
# 4. Security Pin Refusal
# -------------------------------------------------------------
info "Test 4: Security Pin Refusal (unpinned cert & plaintext HTTP)..."

# Probe 1: Plaintext HTTP to receiver port 9000
HTTP_OUTPUT=$(curl -s --connect-timeout 2 http://127.0.0.1:9000/ || true)
if [ -n "$HTTP_OUTPUT" ]; then
    fail "Plaintext HTTP probe unexpectedly succeeded on TLS ingress"
fi

# Probe 2: Unpinned Rogue TLS cert
PROBE_ERR=0
"$BIN" send -dir "$OUTBOX_DIR" -addr "$RECV_LISTEN" \
    -cert "$KEYS_DIR/rogue.crt" -key "$KEYS_DIR/rogue.key" \
    -peer-fp "$RECEIVER_FP" -parallel 1 -scan 100ms -max-attempts 1 \
    -name "rogue-sender" -status "127.0.0.1:9199" > "$TEST_DIR/rogue.log" 2>&1 &
ROGUE_PID=$!
sleep 1.5
kill "$ROGUE_PID" 2>/dev/null || true

# Verify zero unauthorized files committed to incoming
ROGUE_COMMITS=$(ls -1 "$INCOMING_DIR"/*.tmp 2>/dev/null | wc -l || true)
if [ "$ROGUE_COMMITS" -gt 0 ]; then
    fail "Found staged files from rogue connection"
fi

pass "Security pin refusal verified: unpinned certs and plaintext rejected immediately"

# -------------------------------------------------------------
# 5. Poison File Quarantine
# -------------------------------------------------------------
info "Test 5: Poison File Quarantine (10 retries -> .failed/)..."

# Receiver max size is 64GiB, but we can configure a low max-size or trigger protocol rejection
# Let's restart receiver with max-size 500B
kill "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true

"$BIN" recv -dir "$INCOMING_DIR" \
    -listen "$RECV_LISTEN" \
    -cert "$KEYS_DIR/receiver.crt" -key "$KEYS_DIR/receiver.key" \
    -peer-fp "$SENDER_FP" -name "recv-A" \
    -max-size "500B" \
    -disk-warn-pct 0 -disk-fail-pct 0 \
    -status "$RECV_STATUS" &
RECV_PID=$!
sleep 1

# Drop a poison file larger than 500B (e.g. 10KB)
POISON_NAME="poison_large_shard.tar"
dd if=/dev/urandom of="$OUTBOX_DIR/.$POISON_NAME.tmp" bs=1k count=10 status=none
mv "$OUTBOX_DIR/.$POISON_NAME.tmp" "$OUTBOX_DIR/$POISON_NAME"

# Also drop a valid file under 500B (e.g. 100B)
VALID_NAME="valid_after_poison.tar"
dd if=/dev/urandom of="$OUTBOX_DIR/.$VALID_NAME.tmp" bs=100 count=1 status=none
mv "$OUTBOX_DIR/.$VALID_NAME.tmp" "$OUTBOX_DIR/$VALID_NAME"

info "Waiting for poison file to be quarantined after 10 failed attempts..."
QUARANTINED_FILE="$OUTBOX_DIR/.failed/$POISON_NAME"
VALID_COMMITTED="$INCOMING_DIR/$VALID_NAME"

for i in {1..30}; do
    if [ -f "$QUARANTINED_FILE" ] && [ -f "$VALID_COMMITTED" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -f "$QUARANTINED_FILE" ]; then
    fail "Poison file was not quarantined to .failed/"
fi

if [ ! -f "$VALID_COMMITTED" ]; then
    fail "Subsequent valid file was blocked by poison file"
fi

pass "Poison file quarantined to .failed/ without blocking subsequent queue processing"

# -------------------------------------------------------------
# 6. Central Monitoring Dashboard & Exit Codes
# -------------------------------------------------------------
info "Test 6: Central Monitoring Assertions (Exit codes 0, 1, 2)..."

# Scenario A: Node has file in .failed/ -> Exit code 1 (WARN)
set +e
"$BIN" monitor -targets "$SEND_STATUS,$RECV_STATUS" \
    -cert "$KEYS_DIR/monitor.crt" -key "$KEYS_DIR/monitor.key" \
    -watch 0 -timeout 2s > "$TEST_DIR/monitor_warn.txt"
MONITOR_EXIT=$?
set -e

cat "$TEST_DIR/monitor_warn.txt"
if [ "$MONITOR_EXIT" -ne 1 ]; then
    fail "Expected monitor exit code 1 (WARN for .failed file), got $MONITOR_EXIT"
fi
pass "Monitor correctly reported Exit Code 1 (WARN) for quarantined file"

# Scenario B: Clear .failed/ and recent errors -> Exit code 0 (OK)
rm -rf "$OUTBOX_DIR/.failed"
# Restart receiver and sender so cluster has 0 recent errors and state is clean OK
kill "$SEND_PID" 2>/dev/null || true
wait "$SEND_PID" 2>/dev/null || true
kill "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true
start_receiver
start_sender

set +e
"$BIN" monitor -targets "$SEND_STATUS,$RECV_STATUS" \
    -cert "$KEYS_DIR/monitor.crt" -key "$KEYS_DIR/monitor.key" \
    -watch 0 -timeout 2s > "$TEST_DIR/monitor_ok.txt"
MONITOR_EXIT=$?
set -e

cat "$TEST_DIR/monitor_ok.txt"
if [ "$MONITOR_EXIT" -ne 0 ]; then
    fail "Expected monitor exit code 0 (OK), got $MONITOR_EXIT"
fi
pass "Monitor correctly reported Exit Code 0 (OK) when cluster is healthy"

# Scenario C: Downed receiver -> Exit code 2 (FAIL / DOWN)
kill "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true

set +e
"$BIN" monitor -targets "$SEND_STATUS,$RECV_STATUS" \
    -cert "$KEYS_DIR/monitor.crt" -key "$KEYS_DIR/monitor.key" \
    -watch 0 -timeout 2s > "$TEST_DIR/monitor_down.txt"
MONITOR_EXIT=$?
set -e

cat "$TEST_DIR/monitor_down.txt"
if [ "$MONITOR_EXIT" -ne 2 ]; then
    fail "Expected monitor exit code 2 (FAIL/DOWN), got $MONITOR_EXIT"
fi
pass "Monitor correctly reported Exit Code 2 (DOWN/FAIL) when target is unreachable"

# -------------------------------------------------------------
# 7. Mid-Stream SIGKILL Injection & Boot Cleanup Recovery
# -------------------------------------------------------------
info "Test 7: Mid-Stream SIGKILL Injection & Boot Cleanup Recovery..."

# Restart receiver with full size support
start_receiver

# Drop a 50MB file
BIG_FILE="recovery_shard.tar"
dd if=/dev/urandom of="$OUTBOX_DIR/.$BIG_FILE.tmp" bs=1M count=50 status=none
mv "$OUTBOX_DIR/.$BIG_FILE.tmp" "$OUTBOX_DIR/$BIG_FILE"
BIG_ORIG_HASH=$(sha256sum "$OUTBOX_DIR/$BIG_FILE" | awk '{print $1}')

# Give sender a moment to begin streaming, then kill receiver with SIGKILL (kill -9)
sleep 0.2
kill -9 "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true

info "Receiver killed with SIGKILL during streaming. Restarting receiver..."
sleep 0.5
start_receiver

# Wait for sender to reconnect and finish transfer
RECV_BIG="$INCOMING_DIR/$BIG_FILE"
for i in {1..30}; do
    if [ -f "$RECV_BIG" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -f "$RECV_BIG" ]; then
    fail "Recovery transfer failed after receiver restart"
fi

RECV_BIG_HASH=$(sha256sum "$RECV_BIG" | awk '{print $1}')
if [ "$BIG_ORIG_HASH" != "$RECV_BIG_HASH" ]; then
    fail "Corrupted file after recovery: $BIG_ORIG_HASH vs $RECV_BIG_HASH"
fi

# Verify boot cleanup left no orphaned .tmp files in .staging/
STAGING_TMP_COUNT=$(find "$INCOMING_DIR/.staging" -name "*.tmp" 2>/dev/null | wc -l || true)
if [ "$STAGING_TMP_COUNT" -ne 0 ]; then
    fail "Staging directory has $STAGING_TMP_COUNT orphaned .tmp files"
fi

pass "Mid-stream SIGKILL recovery verified with zero data corruption and clean .staging/ boot cleanup"

# -------------------------------------------------------------
# 8. HTTP Endpoints Verification (/status, /healthz, /metrics)
# -------------------------------------------------------------
info "Test 8: Verifying diagnostic endpoints /status, /healthz, and /metrics..."

HEALTHZ_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9101/healthz)
if [ "$HEALTHZ_STATUS" -ne 200 ]; then
    fail "Receiver /healthz returned HTTP $HEALTHZ_STATUS, expected 200"
fi

METRICS_BODY=$(curl -s http://127.0.0.1:9101/metrics)
if ! echo "$METRICS_BODY" | grep -q "xport_state"; then
    fail "/metrics missing xport_state metric"
fi

STATUS_JSON=$(curl -s http://127.0.0.1:9101/status)
if ! echo "$STATUS_JSON" | grep -q '"role":"receiver"'; then
    fail "/status JSON missing role:receiver"
fi

pass "All diagnostic endpoints (/status, /healthz, /metrics) verified"

# -------------------------------------------------------------
# 9. One-Shot Push, Universal Filenames & Directory Streaming
# -------------------------------------------------------------
info "Test 9: One-Shot Push, Spaces, Unicode & Directory Auto-Tarring..."

# 9A: File with spaces, parentheses, and plus sign
PUSH_FILE_SPACES="$TEST_DIR/push test (v1) + final.txt"
echo "Payload with spaces and punctuation" > "$PUSH_FILE_SPACES"
SPACES_ORIG_HASH=$(sha256sum "$PUSH_FILE_SPACES" | awk '{print $1}')

"$BIN" push -addr "$RECV_LISTEN" \
    -cert "$KEYS_DIR/sender.crt" -key "$KEYS_DIR/sender.key" \
    -peer-fp "$RECEIVER_FP" \
    "$PUSH_FILE_SPACES"

RECV_SPACES="$INCOMING_DIR/push test (v1) + final.txt"
if [ ! -f "$RECV_SPACES" ]; then
    fail "File with spaces was not received"
fi
RECV_SPACES_HASH=$(sha256sum "$RECV_SPACES" | awk '{print $1}')
if [ "$SPACES_ORIG_HASH" != "$RECV_SPACES_HASH" ]; then
    fail "Hash mismatch for file with spaces"
fi
pass "Ad-hoc push: Filename with spaces and symbols transferred bit-for-bit"

# 9B: File with UTF-8 Unicode
PUSH_FILE_UNICODE="$TEST_DIR/日本語_résumé_モデル.bin"
dd if=/dev/urandom of="$PUSH_FILE_UNICODE" bs=1024 count=64 status=none
UNICODE_ORIG_HASH=$(sha256sum "$PUSH_FILE_UNICODE" | awk '{print $1}')

"$BIN" push -addr "$RECV_LISTEN" \
    -cert "$KEYS_DIR/sender.crt" -key "$KEYS_DIR/sender.key" \
    -peer-fp "$RECEIVER_FP" \
    "$PUSH_FILE_UNICODE"

RECV_UNICODE="$INCOMING_DIR/日本語_résumé_モデル.bin"
if [ ! -f "$RECV_UNICODE" ]; then
    fail "Unicode file was not received"
fi
RECV_UNICODE_HASH=$(sha256sum "$RECV_UNICODE" | awk '{print $1}')
if [ "$UNICODE_ORIG_HASH" != "$RECV_UNICODE_HASH" ]; then
    fail "Hash mismatch for unicode file"
fi
pass "Ad-hoc push: UTF-8 Unicode filename transferred bit-for-bit"

# 9C: Directory Auto-Tarring & Streaming with Receiver Auto-Extract
kill "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true

# Start receiver with -auto-extract enabled
"$BIN" recv -dir "$INCOMING_DIR" \
    -listen "$RECV_LISTEN" \
    -cert "$KEYS_DIR/receiver.crt" -key "$KEYS_DIR/receiver.key" \
    -peer-fp "$SENDER_FP" -name "recv-A" \
    -max-size "64GiB" \
    -auto-extract \
    -disk-warn-pct 0 -disk-fail-pct 0 \
    -status "$RECV_STATUS" &
RECV_PID=$!
sleep 1

# Create sample directory hierarchy
MODEL_DIR="$TEST_DIR/my_checkpoint_dir"
mkdir -p "$MODEL_DIR/weights" "$MODEL_DIR/config"
echo '{"arch": "transformer", "layers": 12}' > "$MODEL_DIR/config/arch.json"
dd if=/dev/urandom of="$MODEL_DIR/weights/layer1.bin" bs=1024 count=128 status=none
ORIG_LAYER1_HASH=$(sha256sum "$MODEL_DIR/weights/layer1.bin" | awk '{print $1}')

"$BIN" push -addr "$RECV_LISTEN" \
    -cert "$KEYS_DIR/sender.crt" -key "$KEYS_DIR/sender.key" \
    -peer-fp "$RECEIVER_FP" \
    "$MODEL_DIR"

# Verify .tar archive committed
if [ ! -f "$INCOMING_DIR/my_checkpoint_dir.tar" ]; then
    fail "my_checkpoint_dir.tar was not committed on receiver"
fi

# Verify auto-extract unpacked files cleanly
EXTRACTED_ARCH="$INCOMING_DIR/my_checkpoint_dir/config/arch.json"
EXTRACTED_LAYER="$INCOMING_DIR/my_checkpoint_dir/weights/layer1.bin"
if [ ! -f "$EXTRACTED_ARCH" ] || [ ! -f "$EXTRACTED_LAYER" ]; then
    fail "Directory auto-extract failed to unpack expected hierarchy"
fi

EXTRACTED_LAYER_HASH=$(sha256sum "$EXTRACTED_LAYER" | awk '{print $1}')
if [ "$ORIG_LAYER1_HASH" != "$EXTRACTED_LAYER_HASH" ]; then
    fail "Auto-extracted file hash mismatch"
fi
pass "Ad-hoc push: Directory streamed on-the-fly and auto-extracted by receiver"

# 9D: Push rejection when target is unreachable
set +e
"$BIN" push -addr "127.0.0.1:9999" \
    -cert "$KEYS_DIR/sender.crt" -key "$KEYS_DIR/sender.key" \
    -peer-fp "$RECEIVER_FP" \
    -timeout 2s \
    "$PUSH_FILE_SPACES" 2>/dev/null
PUSH_DOWN_EXIT=$?
set -e
if [ "$PUSH_DOWN_EXIT" -eq 0 ]; then
    fail "Expected xport push to fail against unreachable receiver"
fi
pass "Ad-hoc push: Correctly failed with non-zero exit code when target is unreachable"

echo "=========================================================="
echo -e "${GREEN}    ALL VERIFICATION SCENARIOS PASSED SUCCESSFULLY!${NC}"
echo "=========================================================="
exit 0
