#!/bin/zsh
# Full pipeline: restart WeChat, inject at the login screen, wait for you to sign in,
# capture, decrypt, export.
# Usage: ./scripts/capture_login.sh [seconds] [output dir]
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECS="${1:-180}"
OUT="${2:-$ROOT/export}"
exec "$ROOT/target/release/sesame" all --seconds "$SECS" --out "$OUT"
