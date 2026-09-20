#!/usr/bin/env bash
# Build clevr-scan for macOS (arm64 + Intel), Windows and Linux. Pure Go, stdlib
# only, CGO off, so each binary is a single static file that runs on a machine
# with nothing installed. That is the point: the recipient must not have to
# install anything, least of all a runtime from someone they just met.
#
#   ./build.sh
#
# Output in dist/.
set -euo pipefail
cd "$(dirname "$0")"
command -v go >/dev/null 2>&1 || { echo "go not found. Install: brew install go (or https://go.dev/dl)"; exit 1; }
mkdir -p dist
export CGO_ENABLED=0
build () { echo "-- dist/clevr-scan-$3"; GOOS="$1" GOARCH="$2" go build -ldflags="-s -w" -o "dist/clevr-scan-$3" .; }
build darwin  arm64 macos-arm64
build darwin  amd64 macos-intel
build windows amd64 windows.exe
build linux   amd64 linux
echo
ls -lh dist/ | tail -n +2 | awk '{printf "   %-28s %s\n", $9, $5}'
echo
echo "Done. Each file runs on its own, with nothing installed."
