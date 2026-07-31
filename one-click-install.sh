#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
  echo "one-click-install.sh must run as root" >&2
  exit 1
}

for command in curl tar mktemp sha256sum awk; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

ARMWALL_REPO=${ARMWALL_REPO:-rainsmen/armwall}
ARMWALL_GITHUB_URL=${ARMWALL_GITHUB_URL:-https://github.com}
ARMWALL_CODELOAD_URL=${ARMWALL_CODELOAD_URL:-https://codeload.github.com}
ARMWALL_RELEASE=${ARMWALL_RELEASE:-latest}
ARMWALL_ARCHIVE_SHA256=${ARMWALL_ARCHIVE_SHA256:-}

# Backward compatibility: explicitly setting ARMWALL_REF keeps the old source
# installation path. New installs default to verified release assets.
if [ -z "${ARMWALL_INSTALL_CHANNEL:-}" ]; then
  if [ "${ARMWALL_REF+x}" = x ]; then
    ARMWALL_INSTALL_CHANNEL=source
  else
    ARMWALL_INSTALL_CHANNEL=release
  fi
fi
ARMWALL_REF=${ARMWALL_REF:-main}

case "$ARMWALL_INSTALL_CHANNEL" in
  release|source) ;;
  *) echo "ARMWALL_INSTALL_CHANNEL must be release or source" >&2; exit 1;;
esac

safe_identifier() {
  case "$1" in
    ""|*[!A-Za-z0-9._-]*)
      echo "unsafe release tag or source ref: $1" >&2
      exit 1
      ;;
  esac
}

download() {
  url=$1
  destination=$2
  curl -fL --retry 3 --connect-timeout 15 "$url" -o "$destination"
}

case "$(uname -m)" in
  armv6*) ARMWALL_ARCH=armv6;;
  armv7*|armhf) ARMWALL_ARCH=armv7;;
  aarch64|arm64) ARMWALL_ARCH=arm64;;
  x86_64|amd64) ARMWALL_ARCH=amd64;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1;;
esac

ARMWALL_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/armwall-install.XXXXXX")
cleanup() {
  rm -rf -- "$ARMWALL_TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

ARMWALL_SOURCE_DIR="$ARMWALL_TMP_DIR/source"
mkdir -p "$ARMWALL_SOURCE_DIR"

verify_release_asset() {
  asset_name=$1
  asset_path=$2
  expected=$(awk -v name="$asset_name" '
    $2 == name && length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ { hash = $1; count++ }
    END { if (count != 1) exit 1; print hash }
  ' "$ARMWALL_CHECKSUMS") || {
    echo "release checksum is missing or ambiguous for $asset_name" >&2
    exit 1
  }
  printf '%s  %s\n' "$expected" "$asset_path" | sha256sum -c -
}

install_release() {
  if [ "$ARMWALL_RELEASE" = latest ]; then
    echo "Resolving latest stable ArmWall release..."
    effective_url=$(curl -fsSL --retry 3 --connect-timeout 15 \
      -o /dev/null -w '%{url_effective}' \
      "$ARMWALL_GITHUB_URL/$ARMWALL_REPO/releases/latest")
    ARMWALL_RELEASE=${effective_url##*/}
    [ "$ARMWALL_RELEASE" != latest ] || {
      echo "cannot resolve the latest ArmWall release" >&2
      exit 1
    }
  fi
  safe_identifier "$ARMWALL_RELEASE"

  ARMWALL_RELEASE_BASE="$ARMWALL_GITHUB_URL/$ARMWALL_REPO/releases/download/$ARMWALL_RELEASE"
  ARMWALL_BINARY_NAME="armwall-linux-$ARMWALL_ARCH"
  ARMWALL_BINARY="$ARMWALL_TMP_DIR/$ARMWALL_BINARY_NAME"
  ARMWALL_SUPPORT_NAME=armwall-install-files.tar.gz
  ARMWALL_SUPPORT="$ARMWALL_TMP_DIR/$ARMWALL_SUPPORT_NAME"
  ARMWALL_CHECKSUMS="$ARMWALL_TMP_DIR/SHA256SUMS"

  echo "Downloading ArmWall $ARMWALL_RELEASE for $ARMWALL_ARCH..."
  download "$ARMWALL_RELEASE_BASE/SHA256SUMS" "$ARMWALL_CHECKSUMS"
  download "$ARMWALL_RELEASE_BASE/$ARMWALL_BINARY_NAME" "$ARMWALL_BINARY"
  download "$ARMWALL_RELEASE_BASE/$ARMWALL_SUPPORT_NAME" "$ARMWALL_SUPPORT"
  verify_release_asset "$ARMWALL_BINARY_NAME" "$ARMWALL_BINARY"
  verify_release_asset "$ARMWALL_SUPPORT_NAME" "$ARMWALL_SUPPORT"

  tar -xzf "$ARMWALL_SUPPORT" -C "$ARMWALL_SOURCE_DIR"
  chmod 0755 "$ARMWALL_BINARY"
  ARMWALL_INSTALL_BINARY=$ARMWALL_BINARY
}

install_source() {
  safe_identifier "$ARMWALL_REF"
  ARMWALL_ARCHIVE="$ARMWALL_TMP_DIR/armwall.tar.gz"
  ARMWALL_DOWNLOAD_URL="$ARMWALL_CODELOAD_URL/$ARMWALL_REPO/tar.gz/$ARMWALL_REF"
  echo "WARNING: installing unverified source channel $ARMWALL_REPO@$ARMWALL_REF" >&2
  echo "Downloading ArmWall source ($ARMWALL_REPO@$ARMWALL_REF)..."
  download "$ARMWALL_DOWNLOAD_URL" "$ARMWALL_ARCHIVE"
  if [ -n "$ARMWALL_ARCHIVE_SHA256" ]; then
    printf '%s  %s\n' "$ARMWALL_ARCHIVE_SHA256" "$ARMWALL_ARCHIVE" | sha256sum -c -
  else
    echo "WARNING: source archive checksum is not verified" >&2
  fi
  tar -xzf "$ARMWALL_ARCHIVE" -C "$ARMWALL_SOURCE_DIR" --strip-components=1
  ARMWALL_INSTALL_BINARY="$ARMWALL_SOURCE_DIR/armwall-linux-$ARMWALL_ARCH"
}

if [ "$ARMWALL_INSTALL_CHANNEL" = release ]; then
  install_release
else
  install_source
fi

for required in install.sh gateway.sh update-core.sh naive-supervisor.sh uninstall.sh \
  armwall.service armwall-sing-box.service armwall-naive.service \
  armwall-gateway.service armwall-subscription-update.service \
  armwall-subscription-update.timer armwall-rule-update.service \
  armwall-rule-update.timer armwall.logrotate; do
  [ -f "$ARMWALL_SOURCE_DIR/$required" ] || {
    echo "installation package does not contain $required" >&2
    exit 1
  }
done
[ -f "$ARMWALL_INSTALL_BINARY" ] || {
  echo "installation package does not contain armwall-linux-$ARMWALL_ARCH" >&2
  exit 1
}

sh "$ARMWALL_SOURCE_DIR/install.sh" "$ARMWALL_INSTALL_BINARY"
