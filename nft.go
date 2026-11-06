package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// nftRuleset builds the host plumbing as ONE atomic nft transaction in its own table, so
// it never touches other tables (the old panel's, Docker's, ...):
//   - masquerade tunnel traffic that leaves through a non-tunnel interface
//   - clamp TCP MSS to the path MTU for forwarded SYNs
func nftRuleset(pools []netip.Prefix) string {
	ps := make([]string, 0, len(pools))
	for _, p := range pools {
		ps = append(ps, p.String())
	}
	sort.Strings(ps)
	set := strings.Join(ps, ", ")
	return fmt.Sprintf(`table ip vpnlite
delete table ip vpnlite
table ip vpnlite {
	chain post {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "vl*" return
		oifname "ppp*" return
		oifname "vc*" return
		oifname "lo" return
		ip saddr { %[1]s } masquerade
	}
	chain fwd {
		type filter hook forward priority mangle; policy accept;
		ip saddr { %[1]s } tcp flags syn tcp option maxseg size set rt mtu
		ip daddr { %[1]s } tcp flags syn tcp option maxseg size set rt mtu
	}
}
`, set)
}

func applyNft(pools []netip.Prefix) error {
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
	if len(pools) == 0 {
		exec.Command("nft", "delete", "table", "ip", "vpnlite").Run()
		return nil
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftRuleset(pools))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
