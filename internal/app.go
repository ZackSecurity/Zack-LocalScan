// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

// Package internal provides compatibility types for the POC scanner.
// It holds process-wide configuration and shared types used across the scanner.
package internal

import (
	"sync"
)

// ==================== Types ====================

type HostInfo struct {
	Host  string
	Ports string
	Url   string
}

type PocInfo struct {
	Target  string
	PocName string
}

// ==================== Args (simulated CLI flags) ====================

var Args = struct {
	Timeout int
}{
	Timeout: 5,
}

// ==================== Setting (simulated config) ====================

var Setting = struct {
	DnsLog     bool
	PocFull    bool
	PocNum     int
	WebTimeout int
}{
	DnsLog:     true,
	WebTimeout: 5,
}

// ==================== Constants ====================

var (
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
	Accept    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
)

// ==================== Default Credentials (for hydra) ====================
// Note: Brute-force dictionaries are defined per-protocol in pkg/hydra/default_*_authlist.go
// Common passwords: pkg/hydra/default_common_passwords.go

// ==================== PoC Result Collector ====================

// PocResults collects PoC vulnerability findings for the final report.
var PocResults []string
var PocResultsMu sync.Mutex

