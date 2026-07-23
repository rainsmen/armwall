#!/bin/sh
set -eu
install -d -m 0750 /etc/armwall /var/lib/armwall
install -m 0755 armwall /usr/local/bin/armwall
install -m 0644 armwall.service /etc/systemd/system/armwall.service
install -m 0644 armwall-sing-box.service /etc/systemd/system/armwall-sing-box.service
systemctl daemon-reload
systemctl enable --now armwall.service
echo "ArmWall installed at http://<server-ip>:8080"
