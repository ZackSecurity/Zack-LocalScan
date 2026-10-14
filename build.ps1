# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZackSecurity

# Build script for Zack-LocalScan
# Produces plain (unobfuscated) single-file binaries for 3 platforms:
#   linux_amd64, windows_amd64, macOS_arm64
#
# Prerequisites:
#   Go 1.25+ (older toolchains auto-download it via GOTOOLCHAIN=auto)

param(
    [switch]$NoClean      # Keep build artifacts
)

$ErrorActionPreference = "Stop"
$env:CGO_ENABLED = "0"

# ==================== Configuration ====================
$BUILD_DIR  = Join-Path $PSScriptRoot "build"
$MODULE     = "Zack-LocalScan"
$LDFLAGS    = "-s -w"

# Platforms to build
$TARGETS = @(
    @{OS="linux";   ARCH="amd64"; EXT=""},
    @{OS="windows"; ARCH="amd64"; EXT=".exe"},
    @{OS="darwin";  ARCH="arm64"; EXT=""}
)

# ==================== Clean ====================
if (-not $NoClean) {
    Write-Host "=== Cleaning build directory ===" -ForegroundColor Cyan
    if (Test-Path $BUILD_DIR) { Remove-Item -Recurse -Force $BUILD_DIR }
    New-Item -ItemType Directory -Force $BUILD_DIR | Out-Null
}

# ==================== Build ====================
Push-Location $PSScriptRoot

foreach ($t in $TARGETS) {
    $os   = $t.OS
    $arch = $t.ARCH
    $ext  = $t.EXT
    $name = "zack-localscan-${os}-${arch}${ext}"
    $out  = Join-Path $BUILD_DIR $name

    Write-Host "=== Building $os/$arch ===" -ForegroundColor Yellow
    $env:GOOS = $os
    $env:GOARCH = $arch
    go build -trimpath -ldflags $LDFLAGS -o $out .

    if ($LASTEXITCODE -ne 0) {
        Write-Error "BUILD FAILED: $os/$arch"
        Pop-Location
        exit 1
    }

    $sz = (Get-Item $out).Length
    $szMB = "{0:N1}" -f ($sz / 1MB)
    Write-Host "  -> $name  ($szMB MB)" -ForegroundColor Green
}

Pop-Location

# ==================== Summary ====================
Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Get-ChildItem $BUILD_DIR | ForEach-Object {
    $mb = "{0:N1}" -f ($_.Length / 1MB)
    Write-Host "  $($_.Name)  —  $mb MB"
}
