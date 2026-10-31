#!/bin/sh
set -eu

CONFIG_DIR=${ARMWALL_NAIVE_CONFIG_DIR:-/etc/armwall/naive}
LOG_FILE=${ARMWALL_NAIVE_LOG:-/var/log/armwall/naive.log}
CHECK_INTERVAL=${ARMWALL_HEALTH_INTERVAL:-45}
MAX_FAILURES=${ARMWALL_HEALTH_MAX_FAILURES:-3}
HEALTH_URL=${ARMWALL_HEALTH_URL:-http://cp.cloudflare.com/generate_204}
# After a health restart, skip a port for BACKOFF_BASE seconds, doubling on each
# further restart up to BACKOFF_MAX, so a node whose server is down is not
# restarted forever every few minutes.
BACKOFF_BASE=${ARMWALL_HEALTH_BACKOFF_BASE:-300}
BACKOFF_MAX=${ARMWALL_HEALTH_BACKOFF_MAX:-1800}
STARTUP_GRACE=${ARMWALL_HEALTH_STARTUP_GRACE:-15}
RUN_DIR=""

PIDS=""

log(){
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>&1 || true
}

# Signal only the naive processes this supervisor started, tracked by PID.
# Matching command lines (pkill -f) would also hit unrelated processes such as
# an admin shell running "grep naive /etc/armwall/naive".
signal_instances(){
  sig=$1
  for pidfile in "$RUN_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    kill "-$sig" "$(cat "$pidfile")" 2>/dev/null || true
  done
}

instances_alive(){
  for pidfile in "$RUN_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    kill -0 "$(cat "$pidfile")" 2>/dev/null && return 0
  done
  return 1
}

cleanup(){
  # Prevent re-entry
  trap '' EXIT INT TERM
  log "Stopping armwall-naive-supervisor, cleaning up worker processes..."
  # Stop the respawn loops first so they cannot start new instances.
  for pid in $PIDS; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  if [ -n "$RUN_DIR" ]; then
    signal_instances TERM
    waited=0
    while [ "$waited" -lt 15 ] && instances_alive; do
      sleep 0.1
      waited=$((waited + 1))
    done
    if instances_alive; then
      log "Warning: lingering naive processes detected, sending SIGKILL..."
      signal_instances KILL
    fi
    rm -rf "$RUN_DIR"
  fi
}
trap cleanup EXIT
# A signal trap that returns would resume the monitoring loop; exit explicitly.
# SIGTERM is a normal systemd stop, so report success rather than 143.
trap 'cleanup; exit 0' TERM
trap 'cleanup; exit 130' INT

while ! command -v naive >/dev/null 2>&1; do
  sleep 30
done

mkdir -p "$(dirname "$LOG_FILE")"
RUN_DIR=$(mktemp -d)

pidfile_for(){
  echo "$RUN_DIR/$(basename "$1" .json).pid"
}

run_instance(){
  config=$1
  pidfile=$(pidfile_for "$config")
  while [ -f "$config" ]; do
    naive "$config" >> "$LOG_FILE" 2>&1 &
    echo "$!" > "$pidfile"
    wait "$!" || true
    [ -f "$config" ] || break
    sleep 2
  done
  rm -f "$pidfile"
}

for config in "$CONFIG_DIR"/*.json; do
  [ -f "$config" ] || continue
  run_instance "$config" &
  PIDS="$PIDS $!"
done

if [ -z "$PIDS" ]; then
  log "No naive configs found in $CONFIG_DIR, entering idle wait..."
  while :; do sleep 3600 & wait $! || true; done
fi

# Sleep in the background so SIGTERM interrupts the wait immediately.
pause(){
  sleep "$1" &
  wait $! || true
}

config_port(){
  grep -o '"listen": *"[^"]*"' "$1" 2>/dev/null | grep -o '[0-9]\+' | tail -n 1 || true
}

restart_instance(){
  pidfile=$(pidfile_for "$1")
  [ -r "$pidfile" ] || return 0
  pid=$(cat "$pidfile")
  kill -TERM "$pid" 2>/dev/null || true
  sleep 1
  kill -KILL "$pid" 2>/dev/null || true
}

# Probe every due port in parallel so one slow node does not delay the rest.
health_round(){
  now=$(date +%s)
  rm -f "$RUN_DIR"/*.code 2>/dev/null || true
  probe_pids=""
  for config in "$CONFIG_DIR"/*.json; do
    [ -f "$config" ] || continue
    port=$(config_port "$config")
    case "$port" in ''|*[!0-9]*) continue;; esac
    skip_until=0
    eval "skip_until=\${skip_$port:-0}"
    [ "$now" -ge "$skip_until" ] || continue
    (
      code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 -m 6 -x "socks5h://127.0.0.1:$port" "$HEALTH_URL" 2>/dev/null || true)
      printf '%s\n' "${code:-000}" > "$RUN_DIR/$port.code"
    ) &
    probe_pids="$probe_pids $!"
  done
  # Wait only for the probes; a bare wait would also block on run_instance.
  for probe_pid in $probe_pids; do
    wait "$probe_pid" || true
  done

  for config in "$CONFIG_DIR"/*.json; do
    [ -f "$config" ] || continue
    port=$(config_port "$config")
    [ -r "$RUN_DIR/$port.code" ] || continue
    code=$(cat "$RUN_DIR/$port.code")
    eval "fail_count=\${fail_$port:-0}"
    eval "backoff=\${backoff_$port:-0}"
    if [ "$code" = "204" ] || [ "$code" = "200" ]; then
      if [ "$fail_count" -gt 0 ] || [ "$backoff" -gt 0 ]; then
        log "[HEALTH] Port $port recovered (probe HTTP $code)"
      fi
      eval "fail_$port=0 backoff_$port=0 skip_$port=0"
      continue
    fi
    fail_count=$((fail_count + 1))
    log "[HEALTH] Port $port probe failed (HTTP $code, failure $fail_count/$MAX_FAILURES)"
    if [ "$fail_count" -lt "$MAX_FAILURES" ]; then
      eval "fail_$port=$fail_count"
      continue
    fi
    if [ "$backoff" -eq 0 ]; then
      backoff=$BACKOFF_BASE
    else
      backoff=$((backoff * 2))
      [ "$backoff" -le "$BACKOFF_MAX" ] || backoff=$BACKOFF_MAX
    fi
    log "[HEALTH] Port $port failed $MAX_FAILURES times, restarting naive for $config; next check in ${backoff}s"
    restart_instance "$config"
    eval "fail_$port=0 backoff_$port=$backoff skip_$port=$(( $(date +%s) + backoff ))"
  done
}

if ! command -v curl >/dev/null 2>&1; then
  log "[HEALTH] curl not found, health checks disabled"
  wait || true
  exit 0
fi

pause "$STARTUP_GRACE"
while :; do
  health_round
  pause "$CHECK_INTERVAL"
done
