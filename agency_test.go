package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type tclient struct {
	t  *testing.T
	ts *httptest.Server
	c  *http.Client
	h  map[string]string
}

func newTClient(t *testing.T, ts *httptest.Server) *tclient {
	jar, _ := cookiejar.New(nil)
	return &tclient{t: t, ts: ts, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, h: map[string]string{}}
}

func (c *tclient) do(method, path, ctype string, body []byte) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.ts.URL+path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range c.h {
		req.Header.Set(k, v)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (c *tclient) get(path string) map[string]any { _, m := c.do("GET", path, "", nil); return m }
func (c *tclient) form(path string, f url.Values) map[string]any {
	_, m := c.do("POST", path, "application/x-www-form-urlencoded", []byte(f.Encode()))
	return m
}
func (c *tclient) js(path string, v any) map[string]any {
	b, _ := json.Marshal(v)
	_, m := c.do("POST", path, "application/json", b)
	return m
}
func (c *tclient) must(m map[string]any, what string) map[string]any {
	c.t.Helper()
	if m["success"] != true {
		c.t.Fatalf("%s: %v", what, m)
	}
	return m
}
func (c *tclient) login(user, pass string) {
	c.t.Helper()
	c.must(c.form("/login", url.Values{"username": {user}, "password": {pass}}), "login "+user)
}

// botAdd is what the bot sends to create an account.
func botAdd(inbound int, email, pass string, gb float64, days int, also ...int) url.Values {
	c := map[string]any{"email": email, "enable": true, "limitIp": 0, "totalGB": int64(gb * gib), "tgId": 0, "subId": "s" + email,
		"comment": "", "reset": 0, "id": email, "password": pass}
	if days > 0 {
		c["expiryTime"] = time.Now().Add(time.Duration(days) * 24 * time.Hour).UnixMilli()
	}
	b, _ := json.Marshal(map[string]any{"clients": []any{c}})
	f := url.Values{"id": {itoa(inbound)}, "settings": {string(b)}}
	for _, x := range also {
		f.Add("inboundIds", itoa(x))
	}
	if len(also) > 0 {
		f.Add("inboundIds", itoa(inbound))
	}
	return f
}

func agencyEnv(t *testing.T) (*Store, *httptest.Server, *tclient) {
	st := testStore(t)
	seed(st)
	st.st.Inbounds[3] = &Inbound{ID: 3, Remark: "cisco", Enable: true, Port: 443, Protocol: "openconnect", Settings: map[string]any{"key": "PRIVATE"}}
	st.st.Inbounds[1].Settings["caKey"] = "PRIVATE"
	ag, err := OpenAgency(filepath.Join(t.TempDir(), "agency"))
	if err != nil {
		t.Fatal(err)
	}
	old := Ag
	Ag = ag
	t.Cleanup(func() { ag.Close(); Ag = old })
	api := &API{st: st, d: &fakeD{}, base: "/"}
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)
	admin := newTClient(t, ts)
	admin.login("admin", "pw")
	admin.must(admin.js("/panel/agency/settings", AgencySettings{Currency: "T", PerGB: 1000, PerDay: 100, MaxLevels: 3,
		Refund: RefundPolicy{Mode: "prorated", Percent: 100}}), "settings")
	return st, ts, admin
}

func allPerms() AgentPerms {
	return AgentPerms{Create: true, Renew: true, Reset: true, Delete: true, Suspend: true, Edit: true, Bulk: true, SubAgents: true, Transfer: true, API: true}
}

func mkAgent(c *tclient, user string, parent int, p AgentPerms, l AgentLimits, pr AgentPricing) int {
	c.t.Helper()
	m := c.must(c.js("/panel/agency/agents/save", agentSave{Agent: Agent{Username: user, Parent: parent, Enable: true, Perms: p, Limits: l, Pricing: pr}, Password: "pass-" + user}), "create "+user)
	return int(m["obj"].(map[string]any)["id"].(float64))
}

func bal(id int) int64 { return Ag.Balance(id) }

func TestAgencyBotFlow(t *testing.T) {
	st, ts, admin := agencyEnv(t)
	a1 := mkAgent(admin, "rose", 0, allPerms(), AgentLimits{}, AgentPricing{})
	a2 := mkAgent(admin, "lily", 0, allPerms(), AgentLimits{}, AgentPricing{PerGB: 2000})
	admin.must(admin.js(fmt.Sprintf("/panel/agency/agents/%d/wallet", a1), map[string]any{"op": "topup", "amount": 100000}), "topup")
	admin.must(admin.js(fmt.Sprintf("/panel/agency/agents/%d/wallet", a2), map[string]any{"op": "topup", "amount": 3000}), "topup2")

	bot := newTClient(t, ts)
	bot.login("rose", "pass-rose")
	// a sale of 10 GB / 30 days at 1000/GB + 100/day = 13000
	bot.must(bot.form("/panel/api/inbounds/addClient", botAdd(1, "c1", "pw1", 10, 30)), "bot add")
	if b := bal(a1); b < 100000-13000-1 || b > 100000-13000+1 {
		t.Fatalf("balance after sale = %d", b)
	}
	if st.st.Accounts["c1"].Owner != a1 {
		t.Fatal("owner not recorded")
	}
	// duplicate: refused by the core, money back
	before := bal(a1)
	if m := bot.form("/panel/api/inbounds/addClient", botAdd(1, "alice@x", "zz", 1, 1)); m["success"] == true {
		t.Fatal("duplicate accepted")
	}
	if bal(a1) != before {
		t.Fatalf("a refused sale cost money: %d -> %d", before, bal(a1))
	}
	// the reseller sees only its own client, and no private keys
	m := bot.must(bot.get("/panel/api/inbounds/get/1"), "get")
	set := m["obj"].(map[string]any)["settings"].(string)
	if !strings.Contains(set, `"c1"`) || strings.Contains(set, "alice") || strings.Contains(set, "PRIVATE") {
		t.Fatalf("reseller view leaks: %s", set)
	}
	if m := bot.get("/panel/api/inbounds/getClientTraffics/alice@x"); m["success"] == true {
		t.Fatal("reseller read another account")
	}
	// admin-only routes are closed
	if code, _ := bot.do("POST", "/panel/api/inbounds/add", "application/x-www-form-urlencoded", []byte("remark=x&port=9&protocol=openvpn")); code != 403 {
		t.Fatalf("reseller add inbound = %d", code)
	}
	if code, _ := bot.do("GET", "/panel/ui/settings", "", nil); code != 403 {
		t.Fatalf("reseller settings = %d", code)
	}
	// extend like the bot: read, add 5 GB and 10 days, write back with the password as identity
	cl := st.st.Accounts["c1"].client()
	cl.TotalGB += 5 * gib
	cl.ExpiryTime += 10 * dayMs
	b, _ := json.Marshal(map[string]any{"clients": []any{cl}})
	before = bal(a1)
	bot.must(bot.form("/panel/api/inbounds/updateClient/pw1", url.Values{"id": {"1"}, "settings": {string(b)}}), "extend")
	if got := before - bal(a1); got < 5*1000+10*100-1 || got > 5*1000+10*100+1 {
		t.Fatalf("extend cost %d", got)
	}
	// the other reseller has the same password on its own account: identities never cross
	bot2 := newTClient(t, ts)
	bot2.login("lily", "pass-lily")
	if m := bot2.form("/panel/api/inbounds/addClient", botAdd(1, "d1", "pw1", 10, 30)); m["success"] == true {
		t.Fatal("sale above the wallet accepted") // 10 GB at 2000 = 20000 > 3000
	}
	if _, ok := st.st.Accounts["d1"]; ok || bal(a2) != 3000 {
		t.Fatal("a refused sale left traces")
	}
	bot2.must(bot2.form("/panel/api/inbounds/addClient", botAdd(1, "d1", "pw1", 1, 1)), "small sale")
	// rose disables "pw1": only her own account changes
	cl = st.st.Accounts["c1"].client()
	cl.Enable = false
	b, _ = json.Marshal(map[string]any{"clients": []any{cl}})
	bot.must(bot.form("/panel/api/inbounds/updateClient/pw1", url.Values{"id": {"1"}, "settings": {string(b)}}), "disable")
	if st.st.Accounts["c1"].Enable || !st.st.Accounts["d1"].Enable {
		t.Fatal("an identity crossed between resellers")
	}
	if st.st.Accounts["d1"].Owner != a2 {
		t.Fatal("d1 owner")
	}
}

func TestAgencyLimitsAndUnlimited(t *testing.T) {
	st, ts, admin := agencyEnv(t)
	p := allPerms()
	id := mkAgent(admin, "max", 0, p, AgentLimits{MaxCustomers: 2, MaxDays: 31, MaxDevices: 2, Inbounds: []int{1, 2}, CreditLimit: 50000}, AgentPricing{})
	bot := newTClient(t, ts)
	bot.login("max", "pass-max")
	if m := bot.form("/panel/api/inbounds/addClient", botAdd(1, "u0", "p", 1, 0)); m["success"] == true {
		t.Fatal("unlimited time sold without permission")
	}
	if m := bot.form("/panel/api/inbounds/addClient", botAdd(3, "u0", "p", 1, 5)); m["success"] == true {
		t.Fatal("sold a service outside the allowed list")
	}
	if m := bot.form("/panel/api/inbounds/addClient", botAdd(1, "u0", "p", 1, 60)); m["success"] == true {
		t.Fatal("sold more days than allowed")
	}
	bot.must(bot.form("/panel/api/inbounds/addClient", botAdd(1, "u1", "p1", 1, 30)), "u1") // on credit (wallet 0, limit 50000)
	if st.st.Accounts["u1"].LimitIP != 2 {
		t.Fatalf("devices not capped: %d", st.st.Accounts["u1"].LimitIP)
	}
	if bal(id) >= 0 {
		t.Fatal("credit sale did not debit")
	}
	bot.must(bot.form("/panel/api/inbounds/addClient", botAdd(1, "u2", "p2", 1, 30)), "u2")
	if m := bot.form("/panel/api/inbounds/addClient", botAdd(1, "u3", "p3", 1, 30)); m["success"] == true {
		t.Fatal("customer limit ignored")
	}
}

func TestAgencyCascadeAndRefund(t *testing.T) {
	st, ts, admin := agencyEnv(t)
	top := mkAgent(admin, "top", 0, allPerms(), AgentLimits{}, AgentPricing{PerGB: 1000, PerDay: 100})
	admin.must(admin.js(fmt.Sprintf("/panel/agency/agents/%d/wallet", top), map[string]any{"op": "topup", "amount": 1000000}), "topup")
	tc := newTClient(t, ts)
	tc.login("top", "pass-top")
	// a sub-agent may not be priced below its parent
	if m := tc.js("/panel/agency/agents/save", agentSave{Agent: Agent{Username: "cheap", Enable: true, Perms: allPerms(), Pricing: AgentPricing{PerGB: 500}}, Password: "pass-cheap"}); m["success"] == true {
		t.Fatal("underpriced sub-agent accepted")
	}
	sub := mkAgent(tc, "sub", 0, allPerms(), AgentLimits{}, AgentPricing{PerGB: 1500, PerDay: 150})
	if x, _ := Ag.Agent(sub); x.Parent != top {
		t.Fatalf("sub-agent parent = %d", x.Parent)
	}
	tc.must(tc.js(fmt.Sprintf("/panel/agency/agents/%d/wallet", sub), map[string]any{"op": "topup", "amount": 500000}), "sub topup")
	topBefore := bal(top)
	sc := newTClient(t, ts)
	sc.login("sub", "pass-sub")
	sc.must(sc.form("/panel/api/inbounds/addClient", botAdd(1, "s1", "q", 10, 10)), "sub sale")
	subPaid := 500000 - bal(sub)
	topPaid := topBefore - bal(top)
	if subPaid < 16499 || subPaid > 16501 || topPaid < 10999 || topPaid > 11001 {
		t.Fatalf("cascade: sub paid %d (want 16500), top paid %d (want 11000)", subPaid, topPaid)
	}
	// the parent sees the sub-agent's account; the sub-agent cannot see the parent's
	if m := tc.get("/panel/api/inbounds/getClientTraffics/s1"); m["success"] != true {
		t.Fatal("parent cannot see its sub-agent's account")
	}
	// report: top's profit on that sale = 5500
	rep := tc.must(tc.get("/panel/agency/reports"), "report")["obj"].(map[string]any)
	if p := rep["totals"].(map[string]any)["profit"].(float64); p < 5499 || p > 5501 {
		t.Fatalf("profit = %v", p)
	}
	// delete right away: prorated refund gives (almost) everything back to both wallets
	st.st.Accounts["s1"].CreatedAt = nowMs() - 1000
	sc.must(sc.form("/panel/api/inbounds/1/delClientByEmail/s1", nil), "delete")
	if got := 500000 - bal(sub); got > 100 {
		t.Fatalf("sub not refunded: still out %d", got)
	}
	if got := topBefore - bal(top); got > 100 {
		t.Fatalf("top not refunded: still out %d", got)
	}
}

func TestAgencyPlanPrice(t *testing.T) {
	_, ts, admin := agencyEnv(t)
	admin.must(admin.js("/panel/agency/plans/save", Plan{Name: "30G", GB: 30, Days: 30, Price: 7000, Enable: true}), "plan")
	id := mkAgent(admin, "plan1", 0, allPerms(), AgentLimits{CreditLimit: 1 << 40}, AgentPricing{})
	c := newTClient(t, ts)
	c.login("plan1", "pass-plan1")
	c.must(c.form("/panel/api/inbounds/addClient", botAdd(2, "pp", "x", 30, 30)), "plan sale")
	if bal(id) != -7000 {
		t.Fatalf("plan price not used: balance %d", bal(id))
	}
}

func TestAgencyConcurrentSalesNeverOverspend(t *testing.T) {
	st, ts, admin := agencyEnv(t)
	id := mkAgent(admin, "fast", 0, allPerms(), AgentLimits{}, AgentPricing{})
	admin.must(admin.js(fmt.Sprintf("/panel/agency/agents/%d/wallet", id), map[string]any{"op": "topup", "amount": 5 * 1100}), "topup")
	c := newTClient(t, ts)
	c.login("fast", "pass-fast")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.form("/panel/api/inbounds/addClient", botAdd(1, fmt.Sprintf("k%d", i), fmt.Sprintf("p%d", i), 1, 1))
		}(i)
	}
	wg.Wait()
	n := 0
	for _, a := range st.st.Accounts {
		if a.Owner == id {
			n++
		}
	}
	if n != 5 || bal(id) != 0 {
		t.Fatalf("created %d accounts, balance %d (want 5, 0)", n, bal(id))
	}
	// the ledger survives a restart with the same balances
	dir := Ag.dir
	Ag.Close()
	re, err := OpenAgency(dir)
	if err != nil {
		t.Fatal(err)
	}
	if re.Balance(id) != 0 || len(re.ledger) != len(Ag.ledger) {
		t.Fatalf("reopened ledger differs: %d entries vs %d", len(re.ledger), len(Ag.ledger))
	}
	re.Close()
}

func TestAgencyAPIKeyAndImpersonate(t *testing.T) {
	_, ts, admin := agencyEnv(t)
	id := mkAgent(admin, "keys", 0, allPerms(), AgentLimits{}, AgentPricing{})
	c := newTClient(t, ts)
	c.login("keys", "pass-keys")
	key := c.must(c.js("/panel/agency/keys/new", map[string]any{"name": "shop"}), "key")["obj"].(map[string]any)["key"].(string)
	api := newTClient(t, ts)
	api.h["X-API-Key"] = key
	api.must(api.get("/panel/api/inbounds/list"), "list by key")
	if who := api.must(api.get("/panel/agency/whoami"), "whoami")["obj"].(map[string]any); who["role"] != "agent" {
		t.Fatalf("api key role %v", who["role"])
	}
	c.must(c.js("/panel/agency/keys/allow", map[string]any{"allow": []string{"10.9.9.9"}}), "allow")
	if code, _ := api.do("GET", "/panel/api/inbounds/list", "", nil); code != 401 {
		t.Fatalf("key from a foreign IP = %d", code)
	}
	// impersonation
	admin.must(admin.js(fmt.Sprintf("/panel/agency/agents/%d/login", id), nil), "login as")
	who := admin.must(admin.get("/panel/agency/whoami"), "whoami")["obj"].(map[string]any)
	if who["role"] != "agent" || who["impersonated"] != true {
		t.Fatalf("impersonation: %v", who)
	}
	admin.must(admin.js("/panel/agency/back", nil), "back")
	if who := admin.must(admin.get("/panel/agency/whoami"), "whoami")["obj"].(map[string]any); who["role"] != "admin" {
		t.Fatalf("back: %v", who)
	}
}

func TestAgencyBackupRoundTrip(t *testing.T) {
	st, _, admin := agencyEnv(t)
	id := mkAgent(admin, "bkup", 0, allPerms(), AgentLimits{}, AgentPricing{})
	admin.must(admin.js(fmt.Sprintf("/panel/agency/agents/%d/wallet", id), map[string]any{"op": "topup", "amount": 777}), "topup")
	b, err := st.backupBytes()
	if err != nil || !strings.Contains(string(b), `"agency"`) {
		t.Fatalf("backup has no agency data: %v", err)
	}
	var x struct{ Agency agencyExport }
	json.Unmarshal(b, &x)
	Ag.Credit(id, 5, "adjust", "test", "", "")
	if err := Ag.Import(x.Agency); err != nil {
		t.Fatal(err)
	}
	if bal(id) != 777 {
		t.Fatalf("restored balance %d", bal(id))
	}
}
