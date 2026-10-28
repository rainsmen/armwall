#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 1; }
SRC_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REQUESTED_WEB_ACCESS=${ARMWALL_WEB_ACCESS:-}
REQUESTED_WEB_LISTEN=${ARMWALL_LISTEN:-}
REQUESTED_WEB_ALLOWED_CIDRS=${ARMWALL_WEB_ALLOWED_CIDRS:-}
missing=
for command in curl file tar xz nft ip ping sysctl python3 logrotate; do
  command -v "$command" >/dev/null 2>&1 || missing="$missing $command"
done
if [ -n "$missing" ]; then
  command -v apt-get >/dev/null 2>&1 || { echo "missing commands:$missing" >&2; exit 1; }
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl file xz-utils nftables iproute2 iputils-ping procps python3 logrotate
fi
case "$(uname -m)" in
  armv6*) ARMWALL_ARCH=armv6;;
  armv7*|armhf) ARMWALL_ARCH=armv7;;
  aarch64|arm64) ARMWALL_ARCH=arm64;;
  x86_64|amd64) ARMWALL_ARCH=amd64;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1;;
esac
ARMWALL_BINARY=${1:-}
if [ -z "$ARMWALL_BINARY" ]; then
  if [ -f "$SRC_DIR/armwall-linux-$ARMWALL_ARCH" ]; then
    ARMWALL_BINARY="$SRC_DIR/armwall-linux-$ARMWALL_ARCH"
  elif [ -f "$SRC_DIR/armwall" ]; then
    ARMWALL_BINARY="$SRC_DIR/armwall"
  fi
fi
[ -f "$ARMWALL_BINARY" ] || { echo "ArmWall binary not found: $ARMWALL_BINARY" >&2; exit 1; }

generate_token(){
  if [ -n "${ARMWALL_TOKEN:-}" ]; then
    printf '%s\n' "$ARMWALL_TOKEN"
  elif command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
  else
    tr -d '-' < /proc/sys/kernel/random/uuid
  fi
}

env_value(){
  key=$1
  sed -n "s/^${key}=//p" /etc/armwall/armwall.env | tail -1
}

set_env_value(){
  key=$1
  value=$2
  tmp=$(mktemp /etc/armwall/armwall.env.XXXXXX)
  awk -v key="$key" -v value="$value" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 {
      if (!found) print key "=" value
      found = 1
      next
    }
    { print }
    END { if (!found) print key "=" value }
  ' /etc/armwall/armwall.env > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" /etc/armwall/armwall.env
}

resolve_web_settings(){
  ARMWALL_INSTALL_WEB_ACCESS=${REQUESTED_WEB_ACCESS:-lan}
  case "$ARMWALL_INSTALL_WEB_ACCESS" in
    local)
      ARMWALL_INSTALL_LISTEN=${REQUESTED_WEB_LISTEN:-127.0.0.1:8080}
      case "$ARMWALL_INSTALL_LISTEN" in
        127.*:*|localhost:*|'[::1]':*) ;;
        *) echo "local Web access requires a loopback ARMWALL_LISTEN address" >&2; exit 1 ;;
      esac
      ARMWALL_INSTALL_ALLOWED_CIDRS=${REQUESTED_WEB_ALLOWED_CIDRS:-127.0.0.0/8,::1/128}
      ;;
    lan)
      ARMWALL_INSTALL_LISTEN=${REQUESTED_WEB_LISTEN:-0.0.0.0:8080}
      case "$ARMWALL_INSTALL_LISTEN" in
        0.0.0.0:*|:*) ;;
        *) echo "lan Web access requires ARMWALL_LISTEN=0.0.0.0:<port>" >&2; exit 1 ;;
      esac
      ARMWALL_INSTALL_ALLOWED_CIDRS=${REQUESTED_WEB_ALLOWED_CIDRS:-127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}
      ;;
    custom)
      [ -n "$REQUESTED_WEB_LISTEN" ] || { echo "ARMWALL_LISTEN is required for custom Web access" >&2; exit 1; }
      [ -n "$REQUESTED_WEB_ALLOWED_CIDRS" ] || { echo "ARMWALL_WEB_ALLOWED_CIDRS is required for custom Web access" >&2; exit 1; }
      ARMWALL_INSTALL_LISTEN=$REQUESTED_WEB_LISTEN
      ARMWALL_INSTALL_ALLOWED_CIDRS=$REQUESTED_WEB_ALLOWED_CIDRS
      ;;
    *)
      echo "ARMWALL_WEB_ACCESS must be local, lan, or custom" >&2
      exit 1
      ;;
  esac
}

install -d -m 0750 /etc/armwall /var/lib/armwall /var/lib/armwall/backups/config /var/lib/armwall/uploads /var/lib/armwall/rules /var/log/armwall
install -d -m 0755 /etc/logrotate.d
install -m 0755 "$ARMWALL_BINARY" /usr/local/bin/armwall
/usr/local/bin/armwall --version
install -m 0755 "$SRC_DIR/gateway.sh" /usr/local/bin/armwall-gateway
install -m 0755 "$SRC_DIR/update-core.sh" /usr/local/bin/armwall-update-core
install -m 0755 "$SRC_DIR/naive-supervisor.sh" /usr/local/bin/armwall-naive-supervisor
install -m 0755 "$SRC_DIR/uninstall.sh" /usr/local/bin/armwall-uninstall
install -m 0644 "$SRC_DIR/armwall.service" /etc/systemd/system/armwall.service
install -m 0644 "$SRC_DIR/armwall-sing-box.service" /etc/systemd/system/armwall-sing-box.service
install -m 0644 "$SRC_DIR/armwall-naive.service" /etc/systemd/system/armwall-naive.service
install -m 0644 "$SRC_DIR/armwall-gateway.service" /etc/systemd/system/armwall-gateway.service
install -m 0644 "$SRC_DIR/armwall-subscription-update.service" /etc/systemd/system/armwall-subscription-update.service
install -m 0644 "$SRC_DIR/armwall-subscription-update.timer" /etc/systemd/system/armwall-subscription-update.timer
install -m 0644 "$SRC_DIR/armwall-rule-update.service" /etc/systemd/system/armwall-rule-update.service
install -m 0644 "$SRC_DIR/armwall-rule-update.timer" /etc/systemd/system/armwall-rule-update.timer
install -m 0644 "$SRC_DIR/armwall.logrotate" /etc/logrotate.d/armwall
if [ ! -f /etc/armwall/armwall.env ]; then
  ARMWALL_ADMIN_TOKEN=$(generate_token)
  resolve_web_settings
  umask 077
  printf 'ARMWALL_TOKEN=%s\nARMWALL_MAC_ACL_FILE=/etc/armwall/mac-acl.tsv\nARMWALL_WEB_ACCESS=%s\nARMWALL_LISTEN=%s\nARMWALL_WEB_ALLOWED_CIDRS=%s\n' \
    "$ARMWALL_ADMIN_TOKEN" "$ARMWALL_INSTALL_WEB_ACCESS" "$ARMWALL_INSTALL_LISTEN" "$ARMWALL_INSTALL_ALLOWED_CIDRS" \
    > /etc/armwall/armwall.env
else
  ARMWALL_ADMIN_TOKEN=$(sed -n 's/^ARMWALL_TOKEN=//p' /etc/armwall/armwall.env | tail -1)
  if [ "${#ARMWALL_ADMIN_TOKEN}" -lt 16 ]; then
    ARMWALL_ADMIN_TOKEN=$(generate_token)
    umask 077
    printf '\nARMWALL_TOKEN=%s\n' "$ARMWALL_ADMIN_TOKEN" >> /etc/armwall/armwall.env
  fi
  if ! grep -q '^ARMWALL_MAC_ACL_FILE=' /etc/armwall/armwall.env; then
    umask 077
    printf 'ARMWALL_MAC_ACL_FILE=/etc/armwall/mac-acl.tsv\n' >> /etc/armwall/armwall.env
  fi
  if [ -n "$REQUESTED_WEB_ACCESS$REQUESTED_WEB_LISTEN$REQUESTED_WEB_ALLOWED_CIDRS" ]; then
    resolve_web_settings
    set_env_value ARMWALL_WEB_ACCESS "$ARMWALL_INSTALL_WEB_ACCESS"
    set_env_value ARMWALL_LISTEN "$ARMWALL_INSTALL_LISTEN"
    set_env_value ARMWALL_WEB_ALLOWED_CIDRS "$ARMWALL_INSTALL_ALLOWED_CIDRS"
  fi
  chmod 0600 /etc/armwall/armwall.env
fi

if ! command -v sing-box >/dev/null 2>&1; then
  if [ "$ARMWALL_ARCH" = armv6 ]; then
    echo "sing-box has no official ARMv6 release; upload a compatible binary in the Web UI" >&2
  else
    /usr/local/bin/armwall-update-core sing-box latest || echo "sing-box installation failed; retry from the Web UI" >&2
  fi
fi
ARMWALL_CHECK_WEB_ACCESS=$(env_value ARMWALL_WEB_ACCESS)
ARMWALL_CHECK_LISTEN=$(env_value ARMWALL_LISTEN)
ARMWALL_CHECK_ALLOWED_CIDRS=$(env_value ARMWALL_WEB_ALLOWED_CIDRS)
ARMWALL_TOKEN=$ARMWALL_ADMIN_TOKEN \
ARMWALL_WEB_ACCESS=$ARMWALL_CHECK_WEB_ACCESS \
ARMWALL_LISTEN=$ARMWALL_CHECK_LISTEN \
ARMWALL_WEB_ALLOWED_CIDRS=$ARMWALL_CHECK_ALLOWED_CIDRS \
  /usr/local/bin/armwall --check-config
ARMWALL_PROXY_PORT=11080 ARMWALL_TPROXY=1 ARMWALL_TPROXY_PORT=11081 /usr/local/bin/armwall --write-config
systemctl daemon-reload
systemctl enable armwall.service
systemctl enable armwall-subscription-update.timer
systemctl enable armwall-rule-update.timer
systemctl enable armwall-naive.service
systemctl start armwall-rule-update.service || true
systemctl restart armwall.service
systemctl restart armwall-subscription-update.timer
systemctl restart armwall-rule-update.timer
systemctl restart armwall-naive.service
if command -v sing-box >/dev/null 2>&1; then
  systemctl enable armwall-sing-box.service
  systemctl restart armwall-sing-box.service
fi
if [ -z "$ARMWALL_CHECK_WEB_ACCESS" ]; then
  case "$ARMWALL_CHECK_LISTEN" in
    ""|127.*|localhost:*) ARMWALL_CHECK_WEB_ACCESS=local;;
    *) ARMWALL_CHECK_WEB_ACCESS=legacy;;
  esac
fi
if [ -z "$ARMWALL_CHECK_LISTEN" ]; then
  case "$ARMWALL_CHECK_WEB_ACCESS" in
    lan) ARMWALL_CHECK_LISTEN=0.0.0.0:8080;;
    *) ARMWALL_CHECK_LISTEN=127.0.0.1:8080;;
  esac
fi
ARMWALL_WEB_PORT=${ARMWALL_CHECK_LISTEN##*:}
if [ "$ARMWALL_CHECK_WEB_ACCESS" = local ]; then
  echo "ArmWall installed at http://127.0.0.1:$ARMWALL_WEB_PORT"
else
  echo "ArmWall Web access mode: $ARMWALL_CHECK_WEB_ACCESS"
  echo "Candidate addresses (clients must match):"
  echo "Allowed client CIDRs: ${ARMWALL_CHECK_ALLOWED_CIDRS:-unrestricted legacy access}"
  ip -o -4 addr show up scope global 2>/dev/null | awk -v port="$ARMWALL_WEB_PORT" '
    { split($4, address, "/"); print "ArmWall available at http://" address[1] ":" port }
  '
fi
echo "Management token: $ARMWALL_ADMIN_TOKEN"
