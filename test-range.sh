#!/usr/bin/env bash
set -euo pipefail

PROXY_PORT="${PROXY_PORT:-18080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-18081}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$ROOT/.test"
TEST_FILE="$TEST_DIR/test.pkg"
LOG="$TEST_DIR/helper.log"
SETTINGS="$ROOT/data/settings.json"
BACKUP="$TEST_DIR/settings.backup.json"

mkdir -p "$TEST_DIR"
if [ -f "$SETTINGS" ]; then cp "$SETTINGS" "$BACKUP"; else rm -f "$BACKUP"; fi
cleanup() {
  kill "${PID:-}" 2>/dev/null || true
  if [ -f "$BACKUP" ]; then cp "$BACKUP" "$SETTINGS"; else rm -f "$SETTINGS"; fi
}
trap cleanup EXIT

dd if=/dev/zero of="$TEST_FILE" bs=1m count=10 status=none 2>/dev/null || \
  dd if=/dev/zero of="$TEST_FILE" bs=1M count=10 status=none

PROXY_PORT="$PROXY_PORT" DASHBOARD_PORT="$DASHBOARD_PORT" node "$ROOT/src/index.js" > "$LOG" 2>&1 &
PID=$!
sleep 1

curl -fsS -X POST "http://127.0.0.1:$DASHBOARD_PORT/api/local-directory" \
  -H 'Content-Type: application/json' \
  --data "{\"directory\":\"$TEST_DIR\"}" >/dev/null

curl --noproxy '' -fsS -D "$TEST_DIR/headers.txt" \
  --proxy "http://127.0.0.1:$PROXY_PORT" \
  -H 'Range: bytes=0-999999' \
  http://example.test/test.pkg \
  -o "$TEST_DIR/test.part"

BYTES="$(wc -c < "$TEST_DIR/test.part" | tr -d ' ')"
grep -q '206 Partial Content' "$TEST_DIR/headers.txt"
grep -qi 'Content-Range: bytes 0-999999/' "$TEST_DIR/headers.txt"
[ "$BYTES" = "1000000" ]

echo "PASS: local-folder mapping returned 206 and exactly 1,000,000 bytes."
