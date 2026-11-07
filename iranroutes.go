package main

import (
	_ "embed"
	"fmt"
	"net/netip"
	"sort"
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

// ciscoIranRoutes: Cisco/AnyConnect clients cope badly with thousands of split-exclude
// entries, so Cisco gets only the largest ranges (about 91% of Iranian addresses).
const ciscoIranRoutes = 400

// iranLargest returns the n biggest ranges (all of them when n <= 0), in address order.
func iranLargest(n int) []netip.Prefix {
	all := iranPrefixes()
	if n <= 0 || n >= len(all) {
		return all
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Bits() < all[j].Bits() })
	all = all[:n]
	sort.Slice(all, func(i, j int) bool { return all[i].Addr().Less(all[j].Addr()) })
	return all
}

// iranRouteLines renders one line per range using the given format ("%s %s" = address, netmask).
func iranRouteLines(format string, max int) []string {
	var out []string
	for _, p := range iranLargest(max) {
		out = append(out, fmt.Sprintf(format, p.Addr(), prefixMask(p.Bits())))
	}
	return out
}
