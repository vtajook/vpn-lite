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

// ciscoIranRoutes: how many of the largest Iranian ranges Cisco clients reach directly
// (about 84% of Iranian addresses). Several OpenConnect apps ignore the server's split-exclude
// list, so Cisco is given plain routes covering everything except these ranges, which every
// client applies. That costs about 1100 routes; more would be heavy for ocserv and clients.
const ciscoIranRoutes = 200

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

// ciscoPlainRoutes returns routes covering the whole IPv4 space except the n largest Iranian
// ranges and private/special ranges (those stay off the tunnel).
func ciscoPlainRoutes(n int) []netip.Prefix {
	type rng struct{ lo, hi uint64 }
	toRng := func(p netip.Prefix) rng {
		a := p.Addr().As4()
		lo := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
		return rng{lo, lo + uint64(1)<<(32-p.Bits()) - 1}
	}
	var ex []rng
	for _, p := range iranLargest(n) {
		ex = append(ex, toRng(p))
	}
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"} {
		ex = append(ex, toRng(netip.MustParsePrefix(c)))
	}
	sort.Slice(ex, func(i, j int) bool { return ex[i].lo < ex[j].lo })
	var out []netip.Prefix
	emit := func(lo, hi uint64) { // minimal CIDR cover of [lo, hi]
		for lo <= hi {
			size := uint64(1) << 32
			if lo != 0 {
				size = lo & -lo
			}
			for size > hi-lo+1 {
				size >>= 1
			}
			bits := 32
			for s := size; s > 1; s >>= 1 {
				bits--
			}
			out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)}), bits))
			lo += size
		}
	}
	next := uint64(0)
	for _, r := range ex {
		if r.lo > next {
			emit(next, r.lo-1)
		}
		if r.hi+1 > next {
			next = r.hi + 1
		}
	}
	if next <= 0xFFFFFFFF {
		emit(next, 0xFFFFFFFF)
	}
	return out
}
