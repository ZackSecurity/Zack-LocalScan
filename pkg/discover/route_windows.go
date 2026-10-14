// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

//go:build windows

package discover

import (
	"os/exec"
	"strings"
)

// GetRouteSubnets returns private subnets found in the Windows routing table.
// Parses output of "route print -4".
func GetRouteSubnets() []string {
	out, err := exec.Command("route", "print", "-4").Output()
	if err != nil {
		return nil
	}
	return parseRoutePrint(string(out))
}

func parseRoutePrint(output string) []string {
	var subnets []string
	inTable := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// The routing table starts after the "Active Routes" header (English or Chinese Windows).
		if strings.Contains(line, "Active Routes") || strings.Contains(line, "活动路由") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		// Stop at a blank line or the "Persistent Routes" header (English or Chinese Windows).
		if strings.Contains(line, "Persistent Routes") || strings.Contains(line, "永久路由") {
			break
		}
		if strings.HasPrefix(line, "Network Destination") || strings.HasPrefix(line, "网络目标") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		dest := fields[0]
		netmask := fields[1]

		if cidr := ParseRouteDest(dest, netmask); cidr != "" {
			subnets = append(subnets, cidr)
		}
	}
	return dedup(subnets)
}
