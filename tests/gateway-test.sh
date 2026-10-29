#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/bin" "$TMP/state"
cat > "$TMP/bin/ip" <<'EOF'
#!/bin/sh
printf 'ip %s\n' "$*" >> "$TEST_LOG"
case "$1:$2" in
  link:show) exit 0;;
  rule:show) printf '0: from all lookup local\n'; exit 0;;
  route:show) printf 'default via 192.0.2.1 dev wan0 table 233\n'; exit 0;;
  route:add) [ "${FAIL_ROUTE:-0}" = 0 ] || exit 1; exit 0;;
  *) exit 0;;
esac
EOF
cat > "$TMP/bin/nft" <<'EOF'
#!/bin/sh
printf 'nft %s\n' "$*" >> "$TEST_LOG"
case "$1" in
  list) [ "${2:-}" = ruleset ] && exit 0; exit 1;;
  -f) cat "$2" >> "$NFT_LOG"; [ "${FAIL_NFT:-0}" = 0 ];;
  delete) exit 0;;
  *) exit 0;;
esac
EOF
cat > "$TMP/bin/sysctl" <<'EOF'
#!/bin/sh
printf 'sysctl %s\n' "$*" >> "$TEST_LOG"
case "$1" in
  -n) printf '0\n';;
esac
exit 0
EOF
chmod +x "$TMP/bin/ip" "$TMP/bin/nft" "$TMP/bin/sysctl"
export PATH="$TMP/bin:$PATH" TEST_LOG="$TMP/log" NFT_LOG="$TMP/nft-rules"
export ARMWALL_LAN_IF=lan0 ARMWALL_WAN_IF=wan0 ARMWALL_GATEWAY_STATE="$TMP/state/gateway.state"
export ARMWALL_MAC_ACL_FILE="$TMP/missing-acl"

if FAIL_ROUTE=1 "$ROOT/gateway.sh" enable >/dev/null 2>&1; then
  echo "gateway accepted a failed policy route" >&2
  exit 1
fi
grep -F 'ip route add local 0.0.0.0/0 dev lo table 233' "$TEST_LOG" >/dev/null
grep -F 'ip rule del fwmark 0x2333 table 233' "$TEST_LOG" >/dev/null
grep -F 'nft delete table inet armwall' "$TEST_LOG" >/dev/null
grep -F 'sysctl -q -w net.ipv4.ip_forward=0' "$TEST_LOG" >/dev/null
[ ! -e "$ARMWALL_GATEWAY_STATE" ] || { echo "failed enable persisted gateway state" >&2; exit 1; }

: > "$TEST_LOG"
: > "$NFT_LOG"
"$ROOT/gateway.sh" enable >/dev/null
grep -F 'meta nfproto ipv6 fib daddr type local accept' "$NFT_LOG" >/dev/null
grep -F 'icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, nd-redirect } accept' "$NFT_LOG" >/dev/null
[ -r "$ARMWALL_GATEWAY_STATE" ]
printf 'gateway tests passed\n'
