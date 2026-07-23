#!/bin/sh
set -eu
CORE=${1:-}
ACTION=${2:-}
SOURCE=${3:-}
BIN_DIR=${ARMWALL_BIN_DIR:-/usr/local/bin}
BACKUP_DIR=${ARMWALL_BACKUP_DIR:-/var/lib/armwall/backups}

die(){ echo "armwall-update-core: $*" >&2; exit 1; }
arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; armv7*) echo armv7;; armv6*) echo armv6;; *) die "unsupported architecture: $(uname -m)";;
  esac
}
install_binary(){
  src=$1; name=$2
  [ -f "$src" ] || die "file not found: $src"
  file "$src" | grep -q ELF || die "uploaded file is not an ELF executable"
  mkdir -p "$BIN_DIR" "$BACKUP_DIR"
  stamp=$(date +%Y%m%d%H%M%S)
  [ ! -x "$BIN_DIR/$name" ] || cp -p "$BIN_DIR/$name" "$BACKUP_DIR/$name.$stamp"
  install -m 0755 "$src" "$BIN_DIR/$name.new"
  "$BIN_DIR/$name.new" version >/dev/null 2>&1 || { rm -f "$BIN_DIR/$name.new"; die "binary self-check failed"; }
  mv "$BIN_DIR/$name.new" "$BIN_DIR/$name"
}
latest_sing_box(){
  a=$(arch); [ "$a" != armv6 ] || die "official sing-box releases do not provide armv6 builds; use manual"
  version=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | sed -n 's/.*"tag_name": "v\([^"]*\)".*/\1/p' | head -1)
  [ -n "$version" ] || die "cannot determine latest sing-box version"
  url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-linux-$a-glibc.tar.gz"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  curl -fL "$url" -o "$tmp/core.tgz"
  tar -tzf "$tmp/core.tgz" >/dev/null || die "invalid archive"
  tar -xzf "$tmp/core.tgz" -C "$tmp"
  install_binary "$(find "$tmp" -type f -name sing-box | head -1)" sing-box
  systemctl restart armwall-sing-box.service 2>/dev/null || true
  sing-box version
}
case "$CORE:$ACTION" in
  sing-box:version) sing-box version;;
  sing-box:latest) latest_sing_box;;
  sing-box:manual) [ -n "$SOURCE" ] || die "manual requires a file path"; install_binary "$SOURCE" sing-box; systemctl restart armwall-sing-box.service; sing-box version;;
  naive:version) naive --version 2>&1 | head -1;;
  naive:manual) [ -n "$SOURCE" ] || die "manual requires a file path"; install_binary "$SOURCE" naive; naive --version 2>&1 | head -1;;
  *) echo "usage: $0 {sing-box|naive} {version|latest|manual} [file]"; exit 2;;
esac
