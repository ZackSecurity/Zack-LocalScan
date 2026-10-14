// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package osping

import (
	"net"
	"strings"
	"time"
)

// Timeout is the timeout in seconds (controlled by -w flag). Default 2s.
var Timeout = 2

// probePorts are the ports used for TCP-based liveness detection.
// Port roles: 80=HTTP, 443=HTTPS, 22=SSH, 445=SMB (Windows).
// Any TCP response (SYN-ACK or RST) proves the host is alive.
var probePorts = []string{"80", "443", "22", "445"}

// Ping checks if a host is alive by probing common TCP ports.
// Uses Go-native net.DialTimeout — no process spawning, no admin required.
// The TCP stack automatically handles ARP resolution, interface selection,
// and routing, making this reliable on multi-homed machines.
func Ping(host string) bool {
	timeout := time.Duration(Timeout) * time.Second
	for _, port := range probePorts {
		addr := net.JoinHostPort(host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			return true
		}
		// RST (connection refused) also proves the host is alive
		if strings.Contains(err.Error(), "refused") {
			return true
		}
	}
	return false
}
