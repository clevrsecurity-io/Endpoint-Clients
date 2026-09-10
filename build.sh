#!/usr/bin/env bash
# Build standalone single-file executables of the Clevr endpoint agent for macOS
# (arm64 + Intel), Windows (x64) and Linux (x64) — NO runtime required on the target
# machine. Written in Go (stdlib only), so each binary is a ~6 MB static executable
# with nothing to install. Output goes to dist/ (gitignored). Cross-compiles from
# any host (pure Go, CGO off).
#
#   ./build.sh
#
# Requires Go (https://go.dev/dl, or `brew install go`). The Node .mjs
# (clevr-endpoint.mjs) remains as the ~10 KB drop-in for machines that already have
# Node 18+; these binaries are for pushing to machines with no runtime at all.
set -euo pipefail
cd "$(dirname "$0")/go"
command -v go >/dev/null 2>&1 || { echo "go not found. Install: brew install go (or https://go.dev/dl)"; exit 1; }
mkdir -p ../dist
export CGO_ENABLED=0
build () { echo "-- building dist/clevr-endpoint-$3"; GOOS="$1" GOARCH="$2" go build -ldflags="-s -w" -o "../dist/clevr-endpoint-$3" .; }
build darwin  arm64  macos-arm64
build darwin  amd64  macos-x64
build windows amd64  windows-x64.exe
build linux   amd64  linux-x64
echo "Done. Standalone ~6 MB binaries in dist/ (run with no runtime installed)."
