#!/bin/zsh
# Janitor: the hook keeps appending to its log (including a lot of password-derivation
# noise). Every 10 minutes, harvest matchable keys into keys.json and truncate the log.
# Exits when WeChat closes.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="$HOME/Library/Containers/com.tencent.xinWeChat/Data"
# New builds write sesame-keys.jsonl; a process hooked before the rename still writes wxkey-keys.jsonl.
pick_log() {
  if [ -f "$D/sesame-keys.jsonl" ]; then echo "$D/sesame-keys.jsonl"; else echo "$D/wxkey-keys.jsonl"; fi
}
say() { echo "[$(date +%H:%M:%S)] $*"; }

say "janitor started (exits when WeChat closes)"
while pgrep -f "MacOS/WeChat$" >/dev/null; do
  sleep 600
  LOG=$(pick_log)
  [ -f "$LOG" ] || continue
  say "harvest: $("$ROOT/target/release/sesame" import "$LOG" --out "$ROOT/keys.json" 2>&1 | grep matched)"
  : > "$LOG"
done
say "WeChat closed, janitor stopped"
