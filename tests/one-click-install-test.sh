#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/armwall-installer-test.XXXXXX")
cleanup() {
  rm -rf -- "$TEST_DIR"
}
trap cleanup EXIT HUP INT TERM

BIN_DIR="$TEST_DIR/bin"
ASSET_DIR="$TEST_DIR/assets"
SUPPORT_DIR="$TEST_DIR/support"
SOURCE_DIR="$TEST_DIR/source/armwall-main"
mkdir -p "$BIN_DIR" "$ASSET_DIR" "$SUPPORT_DIR" "$SOURCE_DIR"

cat > "$BIN_DIR/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
cat > "$BIN_DIR/uname" <<'EOF'
#!/bin/sh
printf '%s\n' "${TEST_UNAME:-x86_64}"
EOF
cat > "$BIN_DIR/curl" <<'EOF'
#!/bin/sh
destination=
write_effective=0
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) destination=$2; shift 2;;
    -w) write_effective=1; shift 2;;
    -*) shift;;
    *) url=$1; shift;;
  esac
done
if [ "$write_effective" -eq 1 ]; then
  printf '%s/repos/example/armwall/releases/tag/v9.9.9' "$TEST_GITHUB_URL"
  exit 0
fi
name=${url##*/}
cp "$TEST_ASSET_DIR/$name" "$destination"
EOF
chmod 0755 "$BIN_DIR/id" "$BIN_DIR/uname" "$BIN_DIR/curl"

for file in gateway.sh update-core.sh naive-supervisor.sh uninstall.sh \
  armwall.service armwall-sing-box.service armwall-naive.service \
  armwall-gateway.service armwall-subscription-update.service \
  armwall-subscription-update.timer armwall-rule-update.service \
  armwall-rule-update.timer armwall.logrotate; do
  printf 'fixture\n' > "$SUPPORT_DIR/$file"
done
cat > "$SUPPORT_DIR/install.sh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$1" > "$TEST_INSTALL_RESULT"
EOF
chmod 0755 "$SUPPORT_DIR/install.sh"
tar -czf "$ASSET_DIR/armwall-install-files.tar.gz" -C "$SUPPORT_DIR" .
printf 'fixture-amd64\n' > "$ASSET_DIR/armwall-linux-amd64"
(cd "$ASSET_DIR" && sha256sum armwall-linux-amd64 armwall-install-files.tar.gz > SHA256SUMS)
cp -a "$SUPPORT_DIR/." "$SOURCE_DIR/"
printf 'source-fixture-amd64\n' > "$SOURCE_DIR/armwall-linux-amd64"
tar -czf "$ASSET_DIR/main" -C "$TEST_DIR/source" armwall-main

INSTALL_RESULT="$TEST_DIR/install-result"
PATH="$BIN_DIR:$PATH" \
TEST_UNAME=x86_64 \
TEST_GITHUB_URL=https://mock.invalid \
TEST_ASSET_DIR="$ASSET_DIR" \
TEST_INSTALL_RESULT="$INSTALL_RESULT" \
ARMWALL_REPO=example/armwall \
ARMWALL_GITHUB_URL=https://mock.invalid \
  sh "$PROJECT_DIR/one-click-install.sh" >/dev/null

[ -s "$INSTALL_RESULT" ] || {
  echo "release installation did not invoke install.sh" >&2
  exit 1
}
case "$(cat "$INSTALL_RESULT")" in
  */armwall-linux-amd64) ;;
  *) echo "installer selected the wrong architecture" >&2; exit 1;;
esac

rm -f "$INSTALL_RESULT"
PATH="$BIN_DIR:$PATH" \
TEST_UNAME=x86_64 \
TEST_ASSET_DIR="$ASSET_DIR" \
TEST_INSTALL_RESULT="$INSTALL_RESULT" \
ARMWALL_REPO=example/armwall \
ARMWALL_CODELOAD_URL=https://mock.invalid \
ARMWALL_REF=main \
  sh "$PROJECT_DIR/one-click-install.sh" >/dev/null 2>&1
case "$(cat "$INSTALL_RESULT")" in
  */source/armwall-linux-amd64) ;;
  *) echo "ARMWALL_REF did not select the compatible source channel" >&2; exit 1;;
esac

printf 'tampered\n' >> "$ASSET_DIR/armwall-linux-amd64"
if PATH="$BIN_DIR:$PATH" \
  TEST_UNAME=x86_64 \
  TEST_GITHUB_URL=https://mock.invalid \
  TEST_ASSET_DIR="$ASSET_DIR" \
  TEST_INSTALL_RESULT="$INSTALL_RESULT" \
  ARMWALL_REPO=example/armwall \
  ARMWALL_GITHUB_URL=https://mock.invalid \
    sh "$PROJECT_DIR/one-click-install.sh" >/dev/null 2>&1; then
  echo "installer accepted a tampered release binary" >&2
  exit 1
fi

echo "one-click installer tests passed"
