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
LOCK_FILE=${ARMWALL_UPDATE_LOCK:-/var/lock/armwall-update-core.lock}

die(){ echo "armwall-update-core: $*" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v flock >/dev/null 2>&1 || die "flock is required"
command -v readelf >/dev/null 2>&1 || die "readelf is required"
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || die "another core update is already running"
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
  expected_machine=
  case "$(arch)" in
    amd64) expected_machine='Advanced Micro Devices X86-64|x86-64' ;;
    arm64) expected_machine='AArch64' ;;
    armv7|armv6) expected_machine='ARM' ;;
  esac
  machine=$(readelf -h "$src" 2>/dev/null | awk -F: '/^[[:space:]]*Machine:/ {gsub(/^[[:space:]]+/, "", $2); print $2; exit}')
  printf '%s\n' "$machine" | grep -Eq "$expected_machine" || die "ELF architecture mismatch: $machine"
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
      systemctl restart armwall-sing-box.service 2>/dev/null || die "sing-box restart failed after binary restore"
    else
      die "sing-box restart failed and no previous binary is available"
    fi
    die "sing-box restart failed; the previous binary was restored"
  fi
}
restart_naive(){
  systemctl is-active --quiet armwall-naive.service || return 0
  if ! systemctl restart armwall-naive.service; then
    if [ -n "$LAST_BACKUP" ] && [ -f "$LAST_BACKUP" ]; then
      install -m 0755 "$LAST_BACKUP" "$BIN_DIR/naive"
      systemctl restart armwall-naive.service 2>/dev/null || die "NaiveProxy restart failed after binary restore"
    else
      die "NaiveProxy restart failed and no previous binary is available"
    fi
    die "NaiveProxy restart failed; the previous binary was restored"
  fi
}
extract_binary(){
  archive=$1; expected_name=$2; destination=$3
  python3 - "$archive" "$expected_name" "$destination" <<'PY'
import os, posixpath, shutil, sys, tarfile

archive, expected, destination = sys.argv[1:]
matches = []
with tarfile.open(archive, "r:*") as bundle:
    for member in bundle.getmembers():
        name = member.name
        normalized = posixpath.normpath(name)
        if name.startswith("/") or normalized == ".." or normalized.startswith("../") or "/../" in name:
            raise SystemExit("archive contains an unsafe path")
        if member.issym() or member.islnk() or member.isdev():
            raise SystemExit("archive contains a link or device entry")
        if member.isfile() and posixpath.basename(normalized) == expected:
            matches.append(member)
    if len(matches) != 1:
        raise SystemExit("archive must contain exactly one expected executable")
    source = bundle.extractfile(matches[0])
    if source is None:
        raise SystemExit("cannot read executable from archive")
    with source, open(destination, "wb") as output:
        shutil.copyfileobj(source, output)
os.chmod(destination, 0o700)
PY
}
latest_sing_box(){
  a=$(arch); [ "$a" != armv6 ] || die "official sing-box releases do not provide armv6 builds; use manual"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  fetch_file https://api.github.com/repos/SagerNet/sing-box/releases/latest "$tmp/release.json"
  python3 - "$tmp/release.json" "$a" "$tmp/meta" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
tag = data.get("tag_name", "")
version = tag[1:] if tag.startswith("v") else tag
arch = sys.argv[2]
target_name = f"sing-box-{version}-linux-{arch}-glibc.tar.gz"
digest = ""
url = ""
for asset in data.get("assets", []):
    if asset.get("name") == target_name:
        url = asset.get("browser_download_url", "")
        digest = asset.get("digest", "")
        break
if not version or not url or not digest:
    raise SystemExit("release metadata missing version, asset URL, or digest")
with open(sys.argv[3], "w", encoding="utf-8") as out:
    out.write("\t".join((version, url, digest)) + "\n")
PY
  IFS="$(printf '\t')" read -r version url expected_digest < "$tmp/meta" || die "cannot read release metadata"
  printf '%s\n' "$version" | grep -Eq '^[0-9A-Za-z][0-9A-Za-z._+-]*$' || die "invalid release version"
  printf '%s\n' "$url" | grep -Eq '^https://(github\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com)/[^[:space:]]+$' || die "invalid release URL"
  printf '%s\n' "$expected_digest" | grep -Eq '^sha256:[0-9a-fA-F]{64}$' || die "invalid release digest"
  fetch_file "$url" "$tmp/core.tgz"
  expected_hash="${expected_digest#sha256:}"
  actual_hash=$(sha256sum "$tmp/core.tgz" | awk '{print $1}')
  [ "$expected_hash" = "$actual_hash" ] || die "SHA256 mismatch: expected $expected_hash, got $actual_hash"
  extract_binary "$tmp/core.tgz" sing-box "$tmp/sing-box"
  install_binary "$tmp/sing-box" sing-box
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
  python3 - "$tmp/release.json" "$a" "$tmp/meta" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
tag = data.get("tag_name", "")
arch = sys.argv[2]
url = ""
digest = ""
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if name.endswith(f"-linux-{arch}.tar.xz") or name.endswith(f"-linux-{arch}.tar.gz"):
        url = asset.get("browser_download_url", "")
        digest = asset.get("digest", "")
        break
if not tag or not url or not digest:
    raise SystemExit("release metadata missing tag, asset URL, or digest")
with open(sys.argv[3], "w", encoding="utf-8") as out:
    out.write("\t".join((tag, url, digest)) + "\n")
PY
  IFS="$(printf '\t')" read -r tag url expected_digest < "$tmp/meta" || die "cannot read release metadata"
  printf '%s\n' "$tag" | grep -Eq '^[v0-9A-Za-z][0-9A-Za-z._+-]*$' || die "invalid release tag"
  printf '%s\n' "$url" | grep -Eq '^https://(github\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com)/[^[:space:]]+$' || die "invalid release URL"
  printf '%s\n' "$expected_digest" | grep -Eq '^sha256:[0-9a-fA-F]{64}$' || die "invalid release digest"
  case "$url" in
    *.tar.gz) archive="$tmp/core.tar.gz"; fetch_file "$url" "$archive"; expected_format=gzip ;;
    *.tar.xz) archive="$tmp/core.tar.xz"; fetch_file "$url" "$archive"; expected_format=xz ;;
    *) die "unsupported NaiveProxy archive format" ;;
  esac
  expected_hash="${expected_digest#sha256:}"
  actual_hash=$(sha256sum "$archive" | awk '{print $1}')
  [ "$expected_hash" = "$actual_hash" ] || die "SHA256 mismatch: expected $expected_hash, got $actual_hash"
  extract_binary "$archive" naive "$tmp/naive"
  install_binary "$tmp/naive" naive
  naive --version 2>&1 | head -1
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
