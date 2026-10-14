// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

//go:build linux

package discover

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// GetRouteSubnets returns private subnets found in /proc/net/route.
func GetRouteSubnets() []string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()

	var subnets []string
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		dest := hexToIPv4(fields[1])
		mask := hexToIPv4(fields[7])

		if cidr := ParseRouteDest(dest, mask); cidr != "" {
			subnets = append(subnets, cidr)
		}
	}
	return dedup(subnets)
}

// hexToIPv4 converts hex string (little-endian uint32) to dotted-quad IP.
func hexToIPv4(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var v uint32
	fmt.Sscanf(hex, "%x", &v)
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, v)
	return ip.String()
}
