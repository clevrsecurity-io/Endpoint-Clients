#!/usr/bin/env bash
# Build clevr-se-helper, the Secure Enclave helper of the system custody, for
# Apple silicon and Intel Macs (a T2 chip has an enclave too), into
# ../dist/clevr-se-helper. Needs the Xcode command line tools (swiftc), on a Mac.
#
#   ./build.sh
#
# The linker signs it ad hoc, which was enough on 2026-11-06 for a command-line
# process to make and use enclave keys without entitlements. A fleet build
# should carry the organization's Developer ID signature.
set -euo pipefail
cd "$(dirname "$0")"
command -v swiftc >/dev/null 2>&1 || { echo "swiftc not found: xcode-select --install" >&2; exit 1; }
mkdir -p ../dist
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for arch in arm64 x86_64; do
  swiftc -O -target "$arch-apple-macos11" -o "$tmp/clevr-se-helper-$arch" main.swift
done
lipo -create -output ../dist/clevr-se-helper "$tmp/clevr-se-helper-arm64" "$tmp/clevr-se-helper-x86_64"
codesign --force --sign - ../dist/clevr-se-helper
echo "Built ../dist/clevr-se-helper (arm64 + x86_64)."
