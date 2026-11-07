package main

import (
	_ "embed"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
)

// Iranian IPv4 ranges (aggregated RIR data, ipverse/rir-ip, Nov 2026). With "Iran direct"
// switched on, OpenVPN and Cisco clients are told to reach these addresses directly
// instead of through the tunnel. L2TP/IPsec has no server-pushed routes, so it is unaffected.
//
//go:embed iran-ipv4.txt
var iranIPv4 string

var iranDirectOn atomic.Bool

func setIranDirect(on bool) { iranDirectOn.Store(on) }

// iranPrefixes returns the embedded ranges that parse cleanly.
func iranPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, l := range strings.Split(iranIPv4, "\n") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(l)); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}

// iranRouteLines renders one line per range using the given format ("%s %s" = address, netmask).
func iranRouteLines(format string) []string {
	var out []string
	for _, p := range iranPrefixes() {
		out = append(out, fmt.Sprintf(format, p.Addr(), prefixMask(p.Bits())))
	}
	return out
}
