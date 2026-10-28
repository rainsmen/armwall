#!/bin/sh
set -eu
CORE=${1:-}
ACTION=${2:-}
SOURCE=${3:-}
BIN_DIR=${ARMWALL_BIN_DIR:-/usr/local/bin}
BACKUP_DIR=${ARMWALL_BACKUP_DIR:-/var/lib/armwall/backups}
CONFIG=${ARMWALL_CONFIG:-/etc/armwall/sing-box.json}
LAST_BACKUP=
PROXY_PORT=${ARMWALL_PROXY_PORT:-}

die(){ echo "armwall-update-core: $*" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || die "python3 is required"
fetch_file(){
  url=$1; destination=$2
  if [ -n "$PROXY_PORT" ]; then
    if curl -fsSL --connect-timeout 5 --proxy "socks5h://127.0.0.1:$PROXY_PORT" "$url" -o "$destination" 2>/dev/null; then
      return 0
    fi
    rm -f "$destination"
  fi
  curl -fsSL --connect-timeout 10 "$url" -o "$destination"
}
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
  if [ -x "$BIN_DIR/$name" ]; then
    LAST_BACKUP="$BACKUP_DIR/$name.$stamp"
    cp -p "$BIN_DIR/$name" "$LAST_BACKUP"
  fi
  tmp_bin=$(mktemp "$BIN_DIR/.${name}.new.XXXXXX")
  install -m 0755 "$src" "$tmp_bin"
  case "$name" in
    sing-box)
      "$tmp_bin" version >/dev/null 2>&1 || { rm -f "$tmp_bin"; die "binary self-check failed"; }
      [ ! -f "$CONFIG" ] || "$tmp_bin" check -c "$CONFIG" >/dev/null 2>&1 || { rm -f "$tmp_bin"; die "existing configuration is incompatible with the uploaded binary"; }
      ;;
    naive) "$tmp_bin" --version >/dev/null 2>&1 || { rm -f "$tmp_bin"; die "binary self-check failed"; };;
  esac
  mv -f "$tmp_bin" "$BIN_DIR/$name"
  prune_backups "$name"
}
prune_backups(){
  name=$1
  keep=${ARMWALL_BACKUP_KEEP:-3}
  case "$keep" in
    ''|*[!0-9]*) keep=3;;
  esac
  [ "$keep" -gt 0 ] || return 0
  # shellcheck disable=SC2012
  old_files=$(ls -1t "$BACKUP_DIR"/"$name".* 2>/dev/null | tail -n +"$((keep + 1))" || true)
  for file in $old_files; do
    [ -e "$file" ] && rm -f -- "$file"
  done
}
restart_sing_box(){
  [ -f "$CONFIG" ] || return 0
  systemctl is-active --quiet armwall-sing-box.service || return 0
  if ! systemctl restart armwall-sing-box.service; then
    if [ -n "$LAST_BACKUP" ] && [ -f "$LAST_BACKUP" ]; then
      install -m 0755 "$LAST_BACKUP" "$BIN_DIR/sing-box"
      systemctl restart armwall-sing-box.service 2>/dev/null || true
    fi
    die "sing-box restart failed; the previous binary was restored"
  fi
}
latest_sing_box(){
  a=$(arch); [ "$a" != armv6 ] || die "official sing-box releases do not provide armv6 builds; use manual"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  fetch_file https://api.github.com/repos/SagerNet/sing-box/releases/latest "$tmp/release.json"
  version=$(python3 - "$tmp/release.json" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    tag = json.load(fh).get("tag_name", "")
print(tag[1:] if tag.startswith("v") else tag)
PY
)
  [ -n "$version" ] || die "cannot determine latest sing-box version"
  url="https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-linux-$a-glibc.tar.gz"
  fetch_file "$url" "$tmp/core.tgz"
  tar -tzf "$tmp/core.tgz" >/dev/null || die "invalid archive"
  tar -xzf "$tmp/core.tgz" -C "$tmp"
  install_binary "$(find "$tmp" -type f -name sing-box | head -1)" sing-box
  restart_sing_box
  sing-box version
}
latest_naive(){
  case "$(arch)" in
    amd64) a=x64;;
    arm64) a=arm64;;
    armv7) a=arm;;
    armv6) die "automatic NaiveProxy updates are unavailable for ARMv6; use manual upload";;
  esac
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  fetch_file https://api.github.com/repos/klzgrad/naiveproxy/releases/latest "$tmp/release.json"
  tag=$(python3 - "$tmp/release.json" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    print(json.load(fh).get("tag_name", ""))
PY
)
  [ -n "$tag" ] || die "cannot determine latest NaiveProxy version"
  url="https://github.com/klzgrad/naiveproxy/releases/download/$tag/naiveproxy-$tag-linux-$a.tar.xz"
  fetch_file "$url" "$tmp/core.tar.xz"
  tar -tJf "$tmp/core.tar.xz" >/dev/null || die "invalid archive"
  tar -xJf "$tmp/core.tar.xz" -C "$tmp"
  binary=$(find "$tmp" -type f -name naive | head -1)
  [ -n "$binary" ] || die "NaiveProxy binary is missing from the archive"
  install_binary "$binary" naive
  naive --version 2>&1 | head -1
}
restart_naive(){
  systemctl is-active --quiet armwall-naive.service || return 0
  systemctl restart armwall-naive.service
}
case "$CORE:$ACTION" in
  sing-box:version) sing-box version;;
  sing-box:latest) latest_sing_box;;
  sing-box:manual) [ -n "$SOURCE" ] || die "manual requires a file path"; install_binary "$SOURCE" sing-box; restart_sing_box; sing-box version;;
  naive:version) naive --version 2>&1 | head -1;;
  naive:latest) latest_naive; restart_naive;;
  naive:manual) [ -n "$SOURCE" ] || die "manual requires a file path"; install_binary "$SOURCE" naive; restart_naive; naive --version 2>&1 | head -1;;
  *) echo "usage: $0 {sing-box|naive} {version|latest|manual} [file]"; exit 2;;
esac
