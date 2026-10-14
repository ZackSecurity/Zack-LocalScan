#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZackSecurity

# Build script for Zack-LocalScan
# Produces plain (unobfuscated) single-file binaries for 3 platforms:
#   linux_amd64, windows_amd64, macOS_arm64
#
# Prerequisites:
#   Go 1.25+ (older toolchains auto-download it via GOTOOLCHAIN=auto)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

export CGO_ENABLED=0

# ==================== Configuration ====================
LDFLAGS="-s -w"

# ==================== Clean ====================
echo "=== Cleaning build directory ==="
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# ==================== Build ====================
cd "$SCRIPT_DIR"

build_target() {
    local os="$1"
    local arch="$2"
    local ext="$3"
    local name="zack-localscan-${os}-${arch}${ext}"
    local out="$BUILD_DIR/$name"

    echo "=== Building $os/$arch ==="
    GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$out" .

    if [ $? -ne 0 ]; then
        echo "[!] BUILD FAILED: $os/$arch"
        exit 1
    fi

    local sz
    sz=$(stat -f%z "$out" 2>/dev/null || stat -c%s "$out" 2>/dev/null)
    local sz_mb
    sz_mb=$(echo "scale=1; $sz / 1048576" | bc 2>/dev/null || printf "%.1f" $(echo "$sz / 1048576" | bc -l))
    echo "  -> $name  ($sz_mb MB)"
}

build_target "linux"   "amd64" ""
build_target "windows" "amd64" ".exe"
build_target "darwin"  "arm64" ""

# ==================== Summary ====================
echo ""
echo "=== Build Complete ==="
ls -lh "$BUILD_DIR"
