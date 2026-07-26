#!/bin/sh
set -eu
TABLE=armwall
MARK=0x2333
PORT=${ARMWALL_TPROXY_PORT:-11081}
MAC_ACL_FILE=${ARMWALL_MAC_ACL_FILE:-/etc/armwall/mac-acl.tsv}
LAN_IF=${ARMWALL_LAN_IF:-}
WAN_IF=${ARMWALL_WAN_IF:-}

die(){ echo "armwall-gateway: $*" >&2; exit 1; }
detect(){
  [ -c /dev/net/tun ] || die "/dev/net/tun is unavailable"
  command -v nft >/dev/null || die "nftables is required"
  command -v ip >/dev/null || die "iproute2 is required"
  command -v sysctl >/dev/null || die "procps is required"
  [ -n "$LAN_IF" ] || LAN_IF=$(ip -o -4 route show scope link | awk 'NR==1{print $5}')
  [ -n "$WAN_IF" ] || WAN_IF=$(ip -o route show default | awk 'NR==1{print $5}')
  [ -n "$LAN_IF" ] || die "cannot detect LAN interface; set ARMWALL_LAN_IF"
  [ -n "$WAN_IF" ] || die "cannot detect WAN interface; set ARMWALL_WAN_IF"
}
enable_gateway(){
  detect
  mkdir -p /var/lib/armwall
  nft list ruleset > /var/lib/armwall/nft.backup
  sysctl -n net.ipv4.ip_forward > /var/lib/armwall/ip-forward.before
  sysctl -q -w net.ipv4.ip_forward=1
  ip rule add fwmark $MARK table 233 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table 233 2>/dev/null || true
  nft delete table inet $TABLE 2>/dev/null || true
  nft add table inet $TABLE
  nft 'add chain inet armwall prerouting { type filter hook prerouting priority mangle; policy accept; }'
  nft "add rule inet armwall prerouting iifname \"$LAN_IF\" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } return"
  if [ -r "$MAC_ACL_FILE" ]; then
    while IFS="$(printf '\t')" read -r acl_port acl_mac acl_network acl_ports; do
      if [ -z "$acl_port" ] || [ -z "$acl_mac" ]; then
        continue
      fi
      match="add rule inet $TABLE prerouting iifname \"$LAN_IF\" ether saddr $acl_mac"
      case "$acl_network:$acl_ports" in
        any:any) match="$match meta l4proto { tcp, udp }";;
        tcp:any|udp:any) match="$match meta l4proto $acl_network";;
        any:*) ports=$(printf '%s' "$acl_ports" | tr ':' '-'); match="$match meta l4proto { tcp, udp } th dport { $ports }";;
        tcp:*|udp:*) ports=$(printf '%s' "$acl_ports" | tr ':' '-'); match="$match meta l4proto $acl_network $acl_network dport { $ports }";;
        *) die "invalid MAC ACL binding for $acl_mac";;
      esac
      nft "$match meta mark set $MARK tproxy to :$acl_port accept"
    done < "$MAC_ACL_FILE"
  fi
  nft "add rule inet armwall prerouting iifname \"$LAN_IF\" meta l4proto { tcp, udp } meta mark set $MARK tproxy to :$PORT accept"
  echo "enabled on LAN=$LAN_IF WAN=$WAN_IF proxy=$PORT"
}
disable(){
  nft delete table inet $TABLE 2>/dev/null || true
  ip rule del fwmark $MARK table 233 2>/dev/null || true
  ip route flush table 233 2>/dev/null || true
  if [ -r /var/lib/armwall/ip-forward.before ]; then
    previous=$(cat /var/lib/armwall/ip-forward.before)
    case "$previous" in 0|1) sysctl -q -w net.ipv4.ip_forward="$previous";; esac
  fi
  echo disabled
}
status(){ nft list table inet $TABLE 2>/dev/null || echo disabled; ip rule show | grep -F "fwmark $MARK" || true; sysctl net.ipv4.ip_forward; }
case "${1:-}" in enable) enable_gateway;; disable) disable;; status) status;; *) echo "usage: $0 {enable|disable|status}"; exit 2;; esac
