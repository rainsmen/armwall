#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/bin" "$TMP/bin-dir" "$TMP/backups"
cat > "$TMP/bin/uname" <<'EOF'
#!/bin/sh
printf '%s\n' aarch64
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2;;
    -*) shift;;
    *) url=$1; shift;;
  esac
done
case "${url:-}" in
  https://api.github.com/*) cp "$ARMWALL_RELEASE_JSON" "$out";;
  *) exit 9;;
esac
EOF
chmod +x "$TMP/bin/uname" "$TMP/bin/curl"

marker="$TMP/executed"
# shellcheck disable=SC2016
printf '{"tag_name":"v$(touch %s)","assets":[{"name":"sing-box-$(touch %s)-linux-arm64-glibc.tar.gz","browser_download_url":"https://github.com/example/core.tgz","digest":"sha256:%064d"}]}\n' "$marker" "$marker" 0 > "$TMP/release.json"
if PATH="$TMP/bin:$PATH" ARMWALL_RELEASE_JSON="$TMP/release.json" ARMWALL_UPDATE_LOCK="$TMP/lock" ARMWALL_BIN_DIR="$TMP/bin-dir" ARMWALL_BACKUP_DIR="$TMP/backups" "$ROOT/update-core.sh" sing-box latest >/dev/null 2>&1; then
  echo "malicious release tag was accepted" >&2
  exit 1
fi
[ ! -e "$marker" ] || { echo "release metadata executed shell syntax" >&2; exit 1; }

printf '{"tag_name":"v1.2.3","assets":[{"name":"sing-box-1.2.3-linux-arm64-glibc.tar.gz","browser_download_url":"https://github.com/example/core.tgz","digest":""}]}\n' > "$TMP/release.json"
if PATH="$TMP/bin:$PATH" ARMWALL_RELEASE_JSON="$TMP/release.json" ARMWALL_UPDATE_LOCK="$TMP/lock" ARMWALL_BIN_DIR="$TMP/bin-dir" ARMWALL_BACKUP_DIR="$TMP/backups" "$ROOT/update-core.sh" sing-box latest >/dev/null 2>&1; then
  echo "release without a digest was accepted" >&2
  exit 1
fi
[ ! -e "$TMP/bin-dir/sing-box" ] || { echo "unverified binary was installed" >&2; exit 1; }
printf 'core update metadata tests passed\n'
