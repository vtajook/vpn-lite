package main

import "testing"

func TestPeriodTracking(t *testing.T) {
	const day = int64(86400000)
	now := int64(1_800_000_000_000)
	days := func(a *Account) (int64, int64) { return (a.Period + day/2) / day, (a.ExpiryTime - now + day - 1) / day }

	a := &Account{ExpiryTime: now + 120*day}
	a.initPeriod(now)
	if p, l := days(a); p != 120 || l != 120 {
		t.Fatalf("new: %d/%d", p, l)
	}
	// 90 days later: 120/30; one month on top of a running account: 150/60
	later := now + 90*day
	old := a.ExpiryTime
	a.ExpiryTime = max(old, later) + 30*day
	a.shiftPeriod(old, a.ExpiryTime, later)
	if a.Period != 150*day || a.ExpiryTime-later != 60*day {
		t.Fatalf("running renew: period %d left %d", a.Period/day, (a.ExpiryTime-later)/day)
	}
	// expired (120/0) then one month: 150/30, the gap is not counted
	b := &Account{ExpiryTime: now + 120*day}
	b.initPeriod(now)
	t5 := now + 130*day // 10 days after it ended
	old = b.ExpiryTime
	b.ExpiryTime = max(old, t5) + 30*day
	b.shiftPeriod(old, b.ExpiryTime, t5)
	if b.Period != 150*day || b.ExpiryTime-t5 != 30*day {
		t.Fatalf("expired renew: period %d", b.Period/day)
	}
	// unlimited stays without a period; becoming timed starts one
	c := &Account{ExpiryTime: now + 30*day} // expiry already set by the caller
	c.shiftPeriod(0, c.ExpiryTime, now)
	if c.Period != 30*day {
		t.Fatalf("unlimited->timed: %d", c.Period/day)
	}
	c.shiftPeriod(c.ExpiryTime, 0, now)
	if c.Period != 0 {
		t.Fatal("timed->unlimited keeps a period")
	}
	// an account from before tracking (Period 0): backfill from its creation, then renew
	d := &Account{CreatedAt: now - 20*day, ExpiryTime: now + 10*day} // a 30-day account
	d.backfillPeriod(now)
	if d.Period != 30*day {
		t.Fatalf("backfill: %d", d.Period/day)
	}
	e := &Account{CreatedAt: now - 20*day, ExpiryTime: now + 10*day}
	old = e.ExpiryTime
	e.ExpiryTime += 30 * day
	e.shiftPeriod(old, e.ExpiryTime, now)
	if e.Period != 60*day {
		t.Fatalf("legacy renew: %d", e.Period/day)
	}
}

func TestLiveRates(t *testing.T) {
	Sessions = &SessionTable{byID: map[string]*Session{}}
	defer func() { Sessions = &SessionTable{byID: map[string]*Session{}} }()
	now := nowMs()
	s := &Session{ID: "a", Email: "bob", Proto: "openvpn-udp", Start: now - 10000, LastSeen: now - 5000, LastActive: now - 5000}
	Sessions.byID["a"] = s
	Sessions.Touch("a", 500_000, 5_000_000) // 5 s after the previous report
	r := liveRates()["bob"]
	if r[0] < 800_000 || r[0] > 1_200_000 || r[1] < 80_000 || r[1] > 120_000 {
		t.Fatalf("rates down=%d up=%d (want ~1 MB/s and ~100 KB/s)", r[0], r[1])
	}
	s.LastSeen = now - 60_000 // no report for a minute: an OpenVPN session is idle, not "still fast"
	if _, ok := liveRates()["bob"]; ok {
		t.Fatal("a stale session still shows a speed")
	}
}
