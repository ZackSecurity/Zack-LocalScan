// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

// Package discover discovers local private subnets from NICs and static routes.
// Filters to RFC 1918 ranges so the scanner only targets subnets the host can reach.
package discover

import (
	"fmt"
	"net"
	"strings"
)

// rfc1918 holds the three private IPv4 address blocks.
var rfc1918 = []*net.IPNet{
	{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
	{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
}

// isPrivate reports whether cidr is fully contained within any RFC 1918 block.
func isPrivate(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, r := range rfc1918 {
		if r.Contains(network.IP) {
			// Ensure the network is not larger than the RFC block.
			// Compare mask sizes: a /16 inside 10/8 is fine, but 10/8 inside itself should match.
			rMask, _ := r.Mask.Size()
			nMask, _ := network.Mask.Size()
			if nMask >= rMask {
				return true
			}
		}
	}
	return false
}

// GetLocalNICSubnets returns /24 subnets from local NICs that fall within
// RFC 1918 ranges. Loopback, link-local (APIPA), and 0.0.0.0 are skipped.
func GetLocalNICSubnets() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var subnets []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.Equal(net.IPv4zero) {
				continue
			}

			// Use the NIC's actual CIDR, not forced /24.
			// Typical: 172.16.22.194/24 → 172.16.22.0/24.
			// But also handle wider masks: 10.0.0.5/22 → 10.0.0.0/22.
			cidr := ipNet.String()
			if isPrivate(cidr) {
				subnets = append(subnets, canonicalCIDR(cidr))
			}
		}
	}
	return dedup(subnets)
}

// canonicalCIDR ensures the CIDR uses the network address (not the host IP).
func canonicalCIDR(cidr string) string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return network.String()
}


func dedup(strs []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// SubnetSource labels where a subnet was discovered from.
type SubnetSource struct {
	CIDR   string
	Source string // "nic" or "route"
}

// GetAllSubnets aggregates NIC and route subnets, deduplicated.
func GetAllSubnets() []SubnetSource {
	var result []SubnetSource

	for _, s := range GetLocalNICSubnets() {
		result = append(result, SubnetSource{CIDR: s, Source: "nic"})
	}

	routeSubnets := GetRouteSubnets()
	for _, s := range routeSubnets {
		// Check for duplicates
		found := false
		for _, r := range result {
			if r.CIDR == s {
				found = true
				break
			}
		}
		if !found {
			result = append(result, SubnetSource{CIDR: s, Source: "route"})
		}
	}

	return result
}

// ParseRouteDest parses a destination/mask pair from routing table output
// and returns a canonical CIDR string if it falls within RFC 1918.
func ParseRouteDest(dest, netmask string) string {
	ip := net.ParseIP(strings.TrimSpace(dest))
	maskIP := net.ParseIP(strings.TrimSpace(netmask))
	if ip == nil || maskIP == nil {
		return ""
	}
	ip4 := ip.To4()
	mask4 := maskIP.To4()
	if ip4 == nil || mask4 == nil {
		return ""
	}

	// Build CIDR
	ones, _ := net.IPv4Mask(mask4[0], mask4[1], mask4[2], mask4[3]).Size()
	cidr := fmt.Sprintf("%s/%d", ip4.String(), ones)
	c := canonicalCIDR(cidr)
	if isPrivate(c) {
		return c
	}
	return ""
}
