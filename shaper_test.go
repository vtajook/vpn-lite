package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestShaperCommands(t *testing.T) {
	st := testStore(t)
	seed(st)
	st.st.Accounts["alice@x"].SpeedDown, st.st.Accounts["alice@x"].SpeedUp = 2048, 512
	var mu = make(chan string, 64)
	sh := newShaper()
	sh.st = st
	sh.run = func(a ...string) error { mu <- strings.Join(a, " "); return nil }
	sh.route = func(string) string { return "vl1u" }
	sh.show = func(...string) string { return "" }
	sess := &Session{ID: "s", Email: "alice@x", VIP: "10.101.2.5", Proto: "openvpn-udp"}
	sh.Apply(sess)
	var got []string
	deadline := time.After(2 * time.Second)
	for len(got) < 8 {
		select {
		case c := <-mu:
			got = append(got, c)
		case <-deadline:
			t.Fatalf("only got %v", got)
		}
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{"class replace dev vl1u parent 1: classid 1:205 htb rate 16384kbit", "match ip dst 10.101.2.5/32 flowid 1:205",
		"parent ffff: protocol ip prio 517 u32 match ip src 10.101.2.5/32 police rate 4096kbit"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	// a PPP session gets its own tbf instead
	sess2 := &Session{ID: "p", Email: "alice@x", VIP: "10.121.0.9", Dev: "ppp3", Proto: "l2tp"}
	sh.Apply(sess2)
	select {
	case c := <-mu:
		if !strings.HasPrefix(c, "qdisc replace dev ppp3 root tbf rate 16384kbit") {
			t.Fatalf("ppp command %q", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ppp command")
	}
}

func TestNftRuleset(t *testing.T) {
	r := nftRuleset([]netip.Prefix{netip.MustParsePrefix("10.121.0.0/16"), netip.MustParsePrefix("10.101.0.0/16")})
	for _, want := range []string{"delete table ip vpnlite", "10.101.0.0/16, 10.121.0.0/16", "masquerade", `oifname "ppp*" return`, "maxseg size set 1240"} {
		if !strings.Contains(r, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
}
