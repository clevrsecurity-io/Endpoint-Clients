#!/usr/bin/env bash
# Package the built endpoint agent for people who install software rather than
# run binaries: a .dmg for macOS, a .zip for Windows, a .tar.gz for Linux, and
# one SHA256SUMS beside them.
#
#   ./build.sh && ./package.sh
#
# The .dmg needs macOS (hdiutil); the other two build anywhere. Output goes to
# dist/packages.
#
# NOT SIGNED, and that is a purchase rather than a script. Unsigned, macOS says
# the developer cannot be verified and Windows SmartScreen warns on first run.
# Signing needs an Apple Developer ID plus notarisation, and a Windows
# code-signing certificate. Until those exist the packages carry their checksums
# and say so: a download that claims to be signed and is not would be worse.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(grep -m1 'const version' go/main.go | sed 's/.*"\(.*\)".*/\1/')"
[ -n "$VERSION" ] || { echo "no version in go/main.go" >&2; exit 1; }
OUT="dist/packages"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

for f in clevr-endpoint-macos-arm64 clevr-endpoint-macos-x64 clevr-endpoint-windows-x64.exe clevr-endpoint-linux-x64; do
  [ -f "dist/$f" ] || { echo "dist/$f is missing. Run ./build.sh first." >&2; exit 1; }
done
mkdir -p "$OUT"

# The one page each package carries, so a machine that has only the download
# knows what it is and what it does not do.
cat > "$STAGE/READ-ME-FIRST.txt" <<TXT
Clevr endpoint agent ${VERSION}

What it does
  Finds the AI clients and agents on this machine, says which of them are
  governed by Clevr and which are not, and can point them at Clevr by writing a
  Clevr MCP server into their own configuration.

Run it
  macOS and Linux:   ./clevr-endpoint --report
  Windows:           clevr-endpoint-windows-x64.exe --report

  Set the instance and the key first:
    CLEVR_URL=https://your-instance
    CLEVR_API_KEY=clevr_sk_...

  Without --report it prints the posture and sends nothing. --json gives
  machine-readable output. --govern shows what it would write into each client
  configuration, and adding --apply writes it.

This build is not signed
  macOS will say the developer cannot be verified, and Windows SmartScreen will
  warn on first run. Check the download against SHA256SUMS instead:
    shasum -a 256 -c SHA256SUMS
TXT

echo "-- macOS .dmg"
if command -v hdiutil >/dev/null 2>&1; then
  APP="$STAGE/Clevr Endpoint Agent"
  mkdir -p "$APP"
  cp dist/clevr-endpoint-macos-arm64 "$APP/clevr-endpoint-arm64"
  cp dist/clevr-endpoint-macos-x64   "$APP/clevr-endpoint-intel"
  cp "$STAGE/READ-ME-FIRST.txt" "$APP/"
  chmod +x "$APP"/clevr-endpoint-*
  rm -f "$OUT/clevr-endpoint-macos-${VERSION}.dmg"
  hdiutil create -quiet -volname "Clevr Endpoint Agent" -srcfolder "$APP" -ov -format UDZO "$OUT/clevr-endpoint-macos-${VERSION}.dmg"
  echo "   $OUT/clevr-endpoint-macos-${VERSION}.dmg"
else
  echo "   skipped (hdiutil is macOS only)"
fi

echo "-- Windows .zip"
WIN="$STAGE/win"
mkdir -p "$WIN"
cp dist/clevr-endpoint-windows-x64.exe "$WIN/"
cp "$STAGE/READ-ME-FIRST.txt" "$WIN/"
( cd "$WIN" && zip -q -r "$OLDPWD/$OUT/clevr-endpoint-windows-x64-${VERSION}.zip" . )
echo "   $OUT/clevr-endpoint-windows-x64-${VERSION}.zip"

echo "-- Linux .tar.gz"
LIN="$STAGE/linux"
mkdir -p "$LIN"
cp dist/clevr-endpoint-linux-x64 "$LIN/clevr-endpoint"
cp "$STAGE/READ-ME-FIRST.txt" "$LIN/"
chmod +x "$LIN/clevr-endpoint"
tar -czf "$OUT/clevr-endpoint-linux-x64-${VERSION}.tar.gz" -C "$LIN" .
echo "   $OUT/clevr-endpoint-linux-x64-${VERSION}.tar.gz"

echo "-- checksums"
( cd "$OUT" && shasum -a 256 clevr-endpoint-* > SHA256SUMS )
cat "$OUT/SHA256SUMS"
echo ""
echo "Done. Packages in $OUT, unsigned, each carrying READ-ME-FIRST.txt."
