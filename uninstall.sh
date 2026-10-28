#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
  echo "uninstall.sh must run as root" >&2
  exit 1
}

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
fi

echo "This will remove ArmWall service files and binaries."
if [ "$PURGE" -eq 1 ]; then
  echo "It will also delete /etc/armwall, /var/lib/armwall and /var/log/armwall."
fi
printf 'Type YES to continue: '
IFS= read -r answer
[ "$answer" = "YES" ] || exit 1

if [ -x /usr/local/bin/armwall-gateway ]; then
  /usr/local/bin/armwall-gateway disable 2>/dev/null || true
fi

systemctl disable --now \
  armwall.service \
  armwall-sing-box.service \
  armwall-naive.service \
  armwall-gateway.service \
  armwall-subscription-update.timer \
  armwall-rule-update.timer 2>/dev/null || true

rm -f \
  /usr/local/bin/armwall \
  /usr/local/bin/armwall-gateway \
  /usr/local/bin/armwall-update-core \
  /usr/local/bin/armwall-naive-supervisor \
  /usr/local/bin/armwall-uninstall

rm -f \
  /etc/systemd/system/armwall.service \
  /etc/systemd/system/armwall-sing-box.service \
  /etc/systemd/system/armwall-naive.service \
  /etc/systemd/system/armwall-gateway.service \
  /etc/systemd/system/armwall-subscription-update.service \
  /etc/systemd/system/armwall-subscription-update.timer \
  /etc/systemd/system/armwall-rule-update.service \
  /etc/systemd/system/armwall-rule-update.timer \
  /etc/logrotate.d/armwall

systemctl daemon-reload

if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/armwall /var/lib/armwall /var/log/armwall
fi

echo "ArmWall uninstalled."
