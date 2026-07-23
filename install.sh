#!/bin/sh
set -eu
install -d -m 0750 /etc/armwall /var/lib/armwall
install -m 0755 armwall /usr/local/bin/armwall
install -m 0644 armwall.service /etc/systemd/system/armwall.service
install -m 0644 armwall-sing-box.service /etc/systemd/system/armwall-sing-box.service
install -m 0644 armwall-subscription-update.service /etc/systemd/system/armwall-subscription-update.service
install -m 0644 armwall-subscription-update.timer /etc/systemd/system/armwall-subscription-update.timer
systemctl daemon-reload
systemctl enable --now armwall.service
systemctl enable --now armwall-subscription-update.timer
echo "ArmWall installed at http://<server-ip>:8080"
