#!/bin/sh
set -eu
TABLE=armwall
MARK=0x2333
PORT=${ARMWALL_PROXY_PORT:-11080}
LAN_IF=${ARMWALL_LAN_IF:-}
WAN_IF=${ARMWALL_WAN_IF:-}

die(){ echo "armwall-gateway: $*" >&2; exit 1; }
detect(){
  [ -c /dev/net/tun ] || die "/dev/net/tun is unavailable"
  command -v nft >/dev/null || die "nftables is required"
  command -v ip >/dev/null || die "iproute2 is required"
  [ -n "$LAN_IF" ] || LAN_IF=$(ip -o -4 route show scope link | awk 'NR==1{print $5}')
  [ -n "$WAN_IF" ] || WAN_IF=$(ip -o route show default | awk 'NR==1{print $5}')
  [ -n "$LAN_IF" ] || die "cannot detect LAN interface; set ARMWALL_LAN_IF"
  [ -n "$WAN_IF" ] || die "cannot detect WAN interface; set ARMWALL_WAN_IF"
}
enable(){
  detect
  mkdir -p /var/lib/armwall
  nft list ruleset > /var/lib/armwall/nft.backup
  ip rule add fwmark $MARK table 233 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table 233 2>/dev/null || true
  nft delete table inet $TABLE 2>/dev/null || true
  nft add table inet $TABLE
  nft 'add chain inet armwall prerouting { type filter hook prerouting priority mangle; policy accept; }'
  nft "add rule inet armwall prerouting iifname \"$LAN_IF\" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } return"
  nft "add rule inet armwall prerouting iifname \"$LAN_IF\" meta l4proto { tcp, udp } meta mark set $MARK tproxy to :$PORT"
  echo "enabled on LAN=$LAN_IF WAN=$WAN_IF proxy=$PORT"
}
disable(){
  nft delete table inet $TABLE 2>/dev/null || true
  ip rule del fwmark $MARK table 233 2>/dev/null || true
  ip route flush table 233 2>/dev/null || true
  echo disabled
}
status(){ nft list table inet $TABLE 2>/dev/null || echo disabled; ip rule show | grep -F "fwmark $MARK" || true; }
case "${1:-}" in enable) enable;; disable) disable;; status) status;; *) echo "usage: $0 {enable|disable|status}"; exit 2;; esac
