#!/bin/sh
set -eu
TABLE=armwall
MARK=0x2333
PORT=${ARMWALL_TPROXY_PORT:-11081}
MAC_ACL_FILE=${ARMWALL_MAC_ACL_FILE:-/etc/armwall/mac-acl.tsv}
LAN_IF=${ARMWALL_LAN_IF:-}
WAN_IF=${ARMWALL_WAN_IF:-}
STATE_FILE=${ARMWALL_GATEWAY_STATE:-/var/lib/armwall/gateway.state}

die(){ echo "armwall-gateway: $*" >&2; exit 1; }
safe_iface(){
  case "$1" in ''|*[!A-Za-z0-9_.-]*) return 1;; esac
  [ "${#1}" -le 32 ] || return 1
  ip link show dev "$1" >/dev/null 2>&1
}
detect(){
  command -v nft >/dev/null || die "nftables is required"
  command -v ip >/dev/null || die "iproute2 is required"
  command -v sysctl >/dev/null || die "procps is required"
  [ -n "$WAN_IF" ] || WAN_IF=$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
  [ -n "$LAN_IF" ] || LAN_IF=$(ip -o -4 route show scope link 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {dev=$(i+1); if(dev !~ /^(tailscale|docker|veth|tun|wg|dummy|lo)/) {print dev; exit}}}')
  [ -n "$LAN_IF" ] || LAN_IF="$WAN_IF"
  [ -n "$LAN_IF" ] || die "cannot detect LAN interface; set ARMWALL_LAN_IF"
  [ -n "$WAN_IF" ] || WAN_IF="$LAN_IF"
  [ -n "$WAN_IF" ] || die "cannot detect WAN interface; set ARMWALL_WAN_IF"
  safe_iface "$LAN_IF" || die "invalid LAN interface: $LAN_IF"
  safe_iface "$WAN_IF" || die "invalid WAN interface: $WAN_IF"
}
load_state(){
  [ -r "$STATE_FILE" ] || return 1
  IFS="$(printf '\t')" read -r LAN_IF WAN_IF PORT < "$STATE_FILE"
  safe_iface "$LAN_IF" || die "invalid saved LAN interface"
  safe_iface "$WAN_IF" || die "invalid saved WAN interface"
  case "$PORT" in ''|*[!0-9]*) die "invalid saved TProxy port";; esac
  if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    die "invalid saved TProxy port"
  fi
}
apply_gateway(){
  while ip rule del fwmark $MARK table 233 2>/dev/null; do :; done
  ip route flush table 233 2>/dev/null || true
  ip rule add fwmark $MARK table 233
  ip route add local 0.0.0.0/0 dev lo table 233
  nft delete table inet $TABLE 2>/dev/null || true
  nft add table inet $TABLE
  nft 'add chain inet armwall prerouting { type filter hook prerouting priority mangle; policy accept; }'
  nft "add rule inet armwall prerouting iifname \"$LAN_IF\" meta nfproto ipv4 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return"
  if [ -r "$MAC_ACL_FILE" ]; then
    while IFS="$(printf '\t')" read -r acl_port acl_mac acl_network acl_ports; do
      if [ -z "$acl_port" ] || [ -z "$acl_mac" ]; then
        continue
      fi
      match="add rule inet $TABLE prerouting iifname \"$LAN_IF\" meta nfproto ipv4 ether saddr $acl_mac"
      case "$acl_network:$acl_ports" in
        any:any) match="$match meta l4proto { tcp, udp }";;
        tcp:any|udp:any) match="$match meta l4proto $acl_network";;
        any:*) ports=$(printf '%s' "$acl_ports" | tr ':' '-'); match="$match meta l4proto { tcp, udp } th dport { $ports }";;
        tcp:*|udp:*) ports=$(printf '%s' "$acl_ports" | tr ':' '-'); match="$match meta l4proto $acl_network $acl_network dport { $ports }";;
        *) die "invalid MAC ACL binding for $acl_mac";;
      esac
      nft "$match meta mark set $MARK tproxy ip to :$acl_port accept"
    done < "$MAC_ACL_FILE"
  fi
  nft "add rule inet armwall prerouting iifname \"$LAN_IF\" meta nfproto ipv4 meta l4proto { tcp, udp } meta mark set $MARK tproxy ip to :$PORT accept"
  echo "enabled on LAN=$LAN_IF WAN=$WAN_IF proxy=$PORT"
}
enable_gateway(){
  detect
  mkdir -p "$(dirname "$STATE_FILE")"
  if [ ! -r "$STATE_FILE" ]; then
    nft list ruleset > /var/lib/armwall/nft.backup 2>/dev/null
    sysctl -n net.ipv4.ip_forward > /var/lib/armwall/ip-forward.before
  fi
  sysctl -q -w net.ipv4.ip_forward=1
  apply_gateway
  printf '%s\t%s\t%s\n' "$LAN_IF" "$WAN_IF" "$PORT" > "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
}
restore(){
  load_state || { echo disabled; return 0; }
  detect
  sysctl -q -w net.ipv4.ip_forward=1
  apply_gateway
}
reload(){
  load_state || return 0
  detect
  apply_gateway
}
suspend_gateway(){
  nft delete table inet $TABLE 2>/dev/null || true
  while ip rule del fwmark $MARK table 233 2>/dev/null; do :; done
  ip route flush table 233 2>/dev/null || true
  echo suspended
}
disable(){
  suspend_gateway >/dev/null
  if [ -r /var/lib/armwall/ip-forward.before ]; then
    previous=$(cat /var/lib/armwall/ip-forward.before)
    case "$previous" in 0|1) sysctl -q -w net.ipv4.ip_forward="$previous";; esac
  fi
  rm -f "$STATE_FILE"
  echo disabled
}
status(){
  if ! nft list table inet $TABLE 2>/dev/null; then
    if [ -r "$STATE_FILE" ]; then echo suspended; else echo disabled; fi
  fi
  ip rule show | grep -F "fwmark $MARK" || true
  sysctl net.ipv4.ip_forward
}
case "${1:-}" in enable) enable_gateway;; restore) restore;; reload) reload;; suspend) suspend_gateway;; disable) disable;; status) status;; *) echo "usage: $0 {enable|restore|reload|suspend|disable|status}"; exit 2;; esac
