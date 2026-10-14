// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

//go:build darwin

package discover

import (
	"os/exec"
	"strings"
)

// GetRouteSubnets returns private subnets found via "netstat -rn -f inet".
func GetRouteSubnets() []string {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return nil
	}
	return parseNetstat(string(out))
}

func parseNetstat(output string) []string {
	var subnets []string
	inTable := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Internet") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if strings.HasPrefix(line, "Destination") {
			continue
		}
		if strings.HasPrefix(line, "Internet6") {
			break
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		dest := fields[0]

		// netstat -rn shows subnets as CIDR: "172.16.22/24", "10.0.0.0/8"
		// "default" and bare octets (like "127") have no mask — skip those.
		if !strings.Contains(dest, "/") {
			continue
		}

		// macOS may output short-form IPs like "172.16.22/24" (3 octets
		// instead of 4). Go's net.ParseCIDR requires a full dotted-quad,
		// so pad the IP part to 4 octets before canonicalising.
		dest = padIPv4(dest)

		if cidr := canonicalCIDR(dest); cidr != "" {
			if isPrivate(cidr) {
				subnets = append(subnets, cidr)
			}
		}
	}
	return dedup(subnets)
}

// padIPv4 expands a short-form CIDR like "172.16.22/24" → "172.16.22.0/24".
// "10/8" → "10.0.0.0/8". Already-valid "10.0.0.0/8" is returned unchanged.
func padIPv4(cidr string) string {
	slash := strings.LastIndexByte(cidr, '/')
	if slash < 0 {
		return cidr
	}
	ipPart := cidr[:slash]
	maskPart := cidr[slash:]

	octets := strings.Split(ipPart, ".")
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	return strings.Join(octets, ".") + maskPart
}
