#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
SUPERVISOR_PID=""
DECOY_PID=""
finish(){
  [ -z "$SUPERVISOR_PID" ] || kill "$SUPERVISOR_PID" 2>/dev/null || true
  [ -z "$DECOY_PID" ] || kill "$DECOY_PID" 2>/dev/null || true
  pkill -KILL -f "naive $TMP/naive" 2>/dev/null || true
  rm -rf "$TMP"
}
trap finish EXIT INT TERM
mkdir -p "$TMP/bin" "$TMP/naive"
printf '{\n  "listen": "socks://127.0.0.1:12000",\n  "proxy": "https://dead.example"\n}\n' > "$TMP/naive/0001.json"
printf '{\n  "listen": "socks://127.0.0.1:12001",\n  "proxy": "https://ok.example"\n}\n' > "$TMP/naive/0002.json"

cat > "$TMP/bin/naive" <<'EOF'
#!/bin/sh
printf 'start %s\n' "$1" >> "$STARTS_LOG"
# Keep "naive <config>" in the command line, as the real binary does.
while :; do sleep 0.2; done
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
case "$*" in
  *127.0.0.1:12000*) printf '000';;
  *) printf '204';;
esac
EOF
chmod +x "$TMP/bin/naive" "$TMP/bin/curl"

export PATH="$TMP/bin:$PATH" STARTS_LOG="$TMP/starts"
export ARMWALL_NAIVE_CONFIG_DIR="$TMP/naive" ARMWALL_NAIVE_LOG="$TMP/naive.log"
export ARMWALL_HEALTH_INTERVAL=1 ARMWALL_HEALTH_MAX_FAILURES=2 ARMWALL_HEALTH_STARTUP_GRACE=0
export ARMWALL_HEALTH_BACKOFF_BASE=4 ARMWALL_HEALTH_BACKOFF_MAX=8
: > "$STARTS_LOG"

# An unrelated process whose command line mentions the config directory, like
# an admin running "grep naive /etc/armwall/naive". It must never be killed.
sh -c 'while :; do sleep 0.2; done' "naive $TMP/naive/0001.json decoy" &
DECOY_PID=$!

sh "$ROOT/naive-supervisor.sh" &
SUPERVISOR_PID=$!
sleep 9

dead_restarts=$(grep -c 'restarting naive for .*/0001.json' "$TMP/naive.log" || true)
ok_restarts=$(grep -c 'restarting naive for .*/0002.json' "$TMP/naive.log" || true)
# Without backoff a failing port restarts every 2 rounds (~4 times in 9s).
if [ "$dead_restarts" -lt 1 ] || [ "$dead_restarts" -gt 2 ]; then
  echo "expected 1-2 throttled restarts of the dead port, got $dead_restarts" >&2
  cat "$TMP/naive.log" >&2
  exit 1
fi
[ "$ok_restarts" -eq 0 ] || { echo "healthy port was restarted" >&2; exit 1; }
grep -F 'next check in 4s' "$TMP/naive.log" >/dev/null || { echo "backoff not logged" >&2; exit 1; }
[ "$(grep -c '0001.json' "$STARTS_LOG")" -ge 2 ] || { echo "dead instance was not respawned" >&2; exit 1; }

kill -TERM "$SUPERVISOR_PID"
waited=0
while kill -0 "$SUPERVISOR_PID" 2>/dev/null; do
  waited=$((waited + 1))
  [ "$waited" -le 30 ] || { echo "supervisor did not exit within 3s of SIGTERM" >&2; exit 1; }
  sleep 0.1
done
SUPERVISOR_PID=""
kill -0 "$DECOY_PID" 2>/dev/null || { echo "supervisor killed an unrelated process" >&2; exit 1; }
if pgrep -f "naive $TMP/naive/000[12].json\$" >/dev/null 2>&1; then
  echo "naive instances survived supervisor shutdown" >&2
  exit 1
fi
printf 'naive supervisor tests passed\n'
