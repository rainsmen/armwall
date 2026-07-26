#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
  echo "one-click-install.sh must run as root" >&2
  exit 1
}

for command in curl tar mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

ARMWALL_REPO=${ARMWALL_REPO:-rainsmen/armwall}
ARMWALL_REF=${ARMWALL_REF:-main}
ARMWALL_DOWNLOAD_URL="https://codeload.github.com/$ARMWALL_REPO/tar.gz/$ARMWALL_REF"
ARMWALL_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/armwall-install.XXXXXX")

cleanup() {
  rm -rf -- "$ARMWALL_TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

ARMWALL_ARCHIVE="$ARMWALL_TMP_DIR/armwall.tar.gz"
ARMWALL_SOURCE_DIR="$ARMWALL_TMP_DIR/source"
mkdir -p "$ARMWALL_SOURCE_DIR"

echo "Downloading ArmWall ($ARMWALL_REPO@$ARMWALL_REF)..."
curl -fL --retry 3 --connect-timeout 15 \
  "$ARMWALL_DOWNLOAD_URL" \
  -o "$ARMWALL_ARCHIVE"
tar -xzf "$ARMWALL_ARCHIVE" -C "$ARMWALL_SOURCE_DIR" --strip-components=1

[ -f "$ARMWALL_SOURCE_DIR/install.sh" ] || {
  echo "downloaded archive does not contain install.sh" >&2
  exit 1
}

sh "$ARMWALL_SOURCE_DIR/install.sh"
