#!/bin/sh
set -eu
CONFIG_DIR=${ARMWALL_NAIVE_CONFIG_DIR:-/etc/armwall/naive}
LOG_FILE=${ARMWALL_NAIVE_LOG:-/var/log/armwall/naive.log}
PIDS=

cleanup(){
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

while ! command -v naive >/dev/null 2>&1; do
  sleep 30
done

mkdir -p "$(dirname "$LOG_FILE")"
for config in "$CONFIG_DIR"/*.json; do
  [ -f "$config" ] || continue
  naive "$config" >> "$LOG_FILE" 2>&1 &
  PIDS="$PIDS $!"
done

if [ -z "$PIDS" ]; then
  while :; do sleep 3600; done
fi
wait
