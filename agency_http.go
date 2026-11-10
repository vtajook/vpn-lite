package main

// HTTP side of the reseller module: who is calling, the reseller versions of the old API (what
// the bot uses), and the agency endpoints of the panel (/panel/agency/...).
//
// Lock order: the core store first, then the agency store. Code never takes a.st.mu while it
// holds Ag.mu.

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/agency.js
var agencyJSData []byte

func (a *API) agencyJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(agencyJSData)
}

// ---------------------------------------------------------------- request identity

type agCtxKey struct{}

type agCtx struct {
	id       int
	via      string // "cookie", "api" or "imp" (the admin looking through an agent's eyes)
	customer int    // customer record for an account being created
}

func withAgent(r *http.Request, id int, via string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), agCtxKey{}, &agCtx{id: id, via: via}))
}

func agCtxOf(r *http.Request) *agCtx { c, _ := r.Context().Value(agCtxKey{}).(*agCtx); return c }

// agentOf is the reseller making the request (0 = the admin).
func agentOf(r *http.Request) int {
	if c := agCtxOf(r); c != nil {
		return c.id
	}
	return 0
}

func customerOf(r *http.Request) int {
	if c := agCtxOf(r); c != nil {
		return c.customer
	}
	return 0
}

// actorOf names the caller in the ledger and the activity log.
func actorOf(r *http.Request) string {
	c := agCtxOf(r)
	switch {
	case c == nil:
		return "admin"
	case c.via == "api":
		return "api:" + itoa(c.id)
	case c.via == "imp":
		return "admin@agent:" + itoa(c.id)
	}
	return "agent:" + itoa(c.id)
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

const admCookie = "vpn-ui-adm" // the admin's own session, kept while the admin looks through an agent's eyes

// identify reports the caller: (0, "cookie", true) the admin, (id, via, true) a reseller by
// cookie or API key, (_, _, false) nobody. A bad API key or a rate limit is answered here
// (via == "handled").
func (a *API) identify(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	if id, ok := a.st.who(r); ok {
		via := "cookie"
		if id > 0 {
			if c, err := r.Cookie(admCookie); err == nil && a.st.verify(c.Value) {
				via = "imp"
			}
		}
		return id, via, true
	}
	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if key == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			key = strings.TrimSpace(h[7:])
		}
	}
	if key == "" || Ag == nil {
		return 0, "", false
	}
	id, rate, why := Ag.APIAgent(key, clientIP(r))
	if id == 0 {
		apiLogAdd(0, r, why)
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, envelope{false, why, nil})
		return 0, "handled", false
	}
	if !apiRateOK(id, rate) {
		apiLogAdd(id, r, "rate limited")
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, envelope{false, "too many requests: slow down", nil})
		return 0, "handled", false
	}
	apiLogAdd(id, r, "")
	return id, "api", true
}

var apiRL = struct {
	sync.Mutex
	m map[int][2]int64 // agent -> {minute, requests in it}
}{m: map[int][2]int64{}}

func apiRateOK(id, perMin int) bool {
	if perMin <= 0 {
		perMin = 120
	}
	min := time.Now().Unix() / 60
	apiRL.Lock()
	defer apiRL.Unlock()
	w := apiRL.m[id]
	if w[0] != min {
		w = [2]int64{min, 0}
	}
	w[1]++
	apiRL.m[id] = w
	return w[1] <= int64(perMin)
}

type apiLogEntry struct {
	T      int64  `json:"t"`
	Agent  int    `json:"agent"`
	Method string `json:"method"`
	Path   string `json:"path"`
	IP     string `json:"ip"`
	Err    string `json:"err,omitempty"`
}

var apiLog = struct {
	sync.Mutex
	b []apiLogEntry
}{}

func apiLogAdd(id int, r *http.Request, err string) {
	apiLog.Lock()
	apiLog.b = append(apiLog.b, apiLogEntry{nowMs(), id, r.Method, r.URL.Path, clientIP(r), err})
	if len(apiLog.b) > 3000 {
		apiLog.b = append([]apiLogEntry(nil), apiLog.b[len(apiLog.b)-2000:]...)
	}
	apiLog.Unlock()
}

// ---------------------------------------------------------------- scoping helpers

// agSubtree is the agent and everyone below it (the accounts a reseller may manage are the
// ones its subtree owns).
func agSubtree(me int) map[int]bool {
	if Ag == nil || me <= 0 {
		return map[int]bool{}
	}
	Ag.mu.RLock()
	defer Ag.mu.RUnlock()
	return Ag.subtreeLocked(me)
}

func mine(sub map[int]bool, acc *Account) bool { return acc != nil && acc.Owner > 0 && sub[acc.Owner] }

// ownedSet lists (lower-case emails) the accounts the caller may see; nil = the admin, everything.
func (a *API) ownedSet(r *http.Request) map[string]bool {
	me := agentOf(r)
	if me == 0 {
		return nil
	}
	sub := agSubtree(me)
	out := map[string]bool{}
	a.st.mu.RLock()
	for _, acc := range a.st.st.Accounts {
		if mine(sub, acc) {
			out[strings.ToLower(acc.Email)] = true
		}
	}
	a.st.mu.RUnlock()
	return out
}

// findMineLocked is accountByIdentityLocked restricted to the caller's accounts (so a password
// shared with somebody else's account can never pick that account).
func (s *Store) findMineLocked(sub map[int]bool, inboundID int, ident string) *Account {
	if ident == "" {
		return nil
	}
	if acc := s.st.Accounts[ekey(ident)]; mine(sub, acc) && (inboundID == 0 || hasInt(acc.Inbounds, inboundID)) {
		return acc
	}
	for _, acc := range s.st.Accounts {
		if !mine(sub, acc) || (inboundID != 0 && !hasInt(acc.Inbounds, inboundID)) {
			continue
		}
		if acc.Password == ident || strings.EqualFold(acc.Username, ident) {
			return acc
		}
	}
	return nil
}

func agAllowed(me int) map[int]bool {
	Ag.mu.RLock()
	defer Ag.mu.RUnlock()
	return Ag.allowedInboundsLocked(me)
}

func agMaxDevices(me int) int {
	Ag.mu.RLock()
	defer Ag.mu.RUnlock()
	if x := Ag.agentLocked(me); x != nil {
		return x.Limits.MaxDevices
	}
	return 0
}

func clampDevices(n, max int) int {
	if max > 0 && (n <= 0 || n > max) {
		return max
	}
	return n
}

// countsLocked: accounts agent me owns itself, how many of them are usable now, and how many
// it created today.
func (s *Store) countsLocked(me int, now int64) (owned, active, today int) {
	start := dayStart(now)
	for _, acc := range s.st.Accounts {
		if acc.Owner == me {
			owned++
			if statusOf(acc, now) == "active" {
				active++
			}
			if acc.CreatedAt >= start {
				today++
			}
		}
	}
	return
}

func (s *Store) svcLocked(ids []int) string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if in := s.st.Inbounds[id]; in != nil && !seen[in.Protocol] {
			seen[in.Protocol] = true
			out = append(out, in.Protocol)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// agOpMu serialises reseller changes: limit checks (customer counts, daily creates) and the
// charge that follows them must not interleave between two requests.
var agOpMu sync.Mutex

// runCore runs an original (admin) handler into memory and reports whether it succeeded.
func runCore(h http.HandlerFunc, r *http.Request) (*bufWriter, envelope) {
	bw := &bufWriter{h: http.Header{}}
	h(bw, r)
	var env envelope
	json.Unmarshal(bw.buf.Bytes(), &env)
	return bw, env
}

func relay(w http.ResponseWriter, bw *bufWriter) {
	for k, v := range bw.h {
		w.Header()[k] = v
	}
	if bw.code != 0 && bw.code != http.StatusOK {
		w.WriteHeader(bw.code)
	}
	w.Write(bw.buf.Bytes())
}

func setClient(r *http.Request, c clientJSON) {
	b, _ := json.Marshal(map[string]any{"clients": []clientJSON{c}})
	r.Form.Set("settings", string(b))
}

func setIDs(r *http.Request, ids []int) {
	v := make([]string, len(ids))
	for i, x := range ids {
		v[i] = itoa(x)
	}
	r.Form["inboundIds"] = v
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]int(nil), a...), append([]int(nil), b...)
	sort.Ints(x)
	sort.Ints(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func gbOf(bytes int64) float64 { return float64(bytes) / gib }

// ---------------------------------------------------------------- reseller old API

func (a *API) adminBalance(w http.ResponseWriter, r *http.Request) { fail(w, "not a reseller") }

func (a *API) agBalance(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	ag, _ := Ag.Agent(me)
	Ag.mu.RLock()
	cur := Ag.f.Settings.Currency
	Ag.mu.RUnlock()
	limit := max(ag.Limits.CreditLimit, ag.Limits.MaxDebt)
	ok(w, "", map[string]any{"balance": Ag.Balance(me), "currency": cur, "creditLimit": limit, "username": ag.Username})
}

// agInboundView is the inbound object a reseller sees: only its own clients, and no private keys.
func (a *API) agInboundViewLocked(in *Inbound, withClients bool, sub map[int]bool) inboundView {
	v := a.st.viewInboundLockedF(in, withClients, func(acc *Account) bool { return mine(sub, acc) })
	for _, k := range []string{"caKey", "serverKey", "key", "tlsCrypt"} {
		delete(v.set, k)
	}
	return v
}

func (a *API) agVisibleLocked(in *Inbound, allow map[int]bool, sub map[int]bool) bool {
	if allow == nil || allow[in.ID] {
		return true
	}
	for _, acc := range a.st.st.Accounts {
		if mine(sub, acc) && hasInt(acc.Inbounds, in.ID) {
			return true
		}
	}
	return false
}

func (a *API) agList(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	sub, allow := agSubtree(me), agAllowed(me)
	light := r.URL.Query().Get("light") == "1"
	a.st.mu.RLock()
	var views []inboundView
	for _, in := range a.st.sortedInbounds() {
		if a.agVisibleLocked(in, allow, sub) {
			views = append(views, a.agInboundViewLocked(in, !light, sub))
		}
	}
	a.st.mu.RUnlock()
	out := make([]inboundJSON, 0, len(views))
	for _, v := range views {
		out = append(out, v.render())
	}
	ok(w, "", out)
}

func (a *API) agGet(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	sub, allow := agSubtree(me), agAllowed(me)
	a.st.mu.RLock()
	in := a.st.st.Inbounds[pathID(r)]
	var v inboundView
	if in != nil && a.agVisibleLocked(in, allow, sub) {
		v = a.agInboundViewLocked(in, true, sub)
	} else {
		in = nil
	}
	a.st.mu.RUnlock()
	if in == nil {
		fail(w, "Inbound not found")
		return
	}
	ok(w, "", v.render())
}

func (a *API) agClientTraffic(w http.ResponseWriter, r *http.Request) {
	sub := agSubtree(agentOf(r))
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	var acc *Account
	if e := r.PathValue("email"); e != "" {
		if x := a.st.st.Accounts[ekey(e)]; mine(sub, x) {
			acc = x
		}
	} else if id := r.PathValue("id"); id != "" {
		acc = a.st.findMineLocked(sub, 0, id)
	}
	if acc == nil {
		fail(w, "Client not found")
		return
	}
	ok(w, "", acc.traffic())
}

func (a *API) agOvpn(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	sub, allow := agSubtree(me), agAllowed(me)
	id := pathID(r)
	a.st.mu.RLock()
	in := a.st.st.Inbounds[id]
	visible := in != nil && a.agVisibleLocked(in, allow, sub)
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	var acc *Account
	if user != "" {
		acc = a.st.findMineLocked(sub, id, user)
	}
	email := ""
	if acc != nil {
		email = acc.Email
	}
	a.st.mu.RUnlock()
	if !visible || (user != "" && acc == nil) {
		fail(w, "Inbound not found")
		return
	}
	if email != "" { // the core looks the user up again: give it the unique name
		q := r.URL.Query()
		q.Set("user", email)
		r.URL.RawQuery = q.Encode()
	}
	a.ovpnFile(w, r)
}

func (a *API) agClientIps(w http.ResponseWriter, r *http.Request) {
	sub := agSubtree(agentOf(r))
	a.st.mu.RLock()
	okk := mine(sub, a.st.st.Accounts[ekey(r.PathValue("email"))])
	a.st.mu.RUnlock()
	if !okk {
		fail(w, "Client not found")
		return
	}
	a.clientIps(w, r)
}

func (a *API) agOnlines(w http.ResponseWriter, r *http.Request) {
	own := a.ownedSet(r)
	out := []string{}
	for e := range a.d.Online() {
		if own[strings.ToLower(e)] {
			out = append(out, e)
		}
	}
	sort.Strings(out)
	ok(w, "", out)
}

func (a *API) agLastOnline(w http.ResponseWriter, r *http.Request) {
	sub := agSubtree(agentOf(r))
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	out := map[string]int64{}
	for _, acc := range a.st.st.Accounts {
		if acc.LastOnline > 0 && mine(sub, acc) {
			out[acc.Email] = acc.LastOnline
		}
	}
	ok(w, "", out)
}

func (a *API) agAddClient(w http.ResponseWriter, r *http.Request) {
	agOpMu.Lock()
	defer agOpMu.Unlock()
	target, _ := strconv.Atoi(r.Form.Get("id"))
	c, msg := parseClient(r, clientJSON{Enable: true})
	if msg != "" {
		fail(w, msg)
		return
	}
	ids, _ := membership(r, target)
	a.agCreate(w, r, sellSpec{c: c, ids: ids, singleSet: strings.Contains(r.Form.Get("settings"), `"singleProto"`)})
}

type sellSpec struct {
	c         clientJSON
	ids       []int
	plan      int // a plan chosen in the agency page; 0 = the plan whose quota and time match, if any
	customer  int
	singleSet bool
}

// agCreate sells a new account: limits, price, payment, then the core creates it; a refusal by
// the core gives the money back. Callers hold agOpMu.
func (a *API) agCreate(w http.ResponseWriter, r *http.Request, s sellSpec) {
	me := agentOf(r)
	now := nowMs()
	c := s.c
	c.Email = strings.TrimSpace(c.Email)
	if c.Email == "" {
		fail(w, "client email is empty")
		return
	}
	if c.Password == "" {
		fail(w, "client password is empty")
		return
	}
	if len(s.ids) == 0 {
		fail(w, "choose at least one service")
		return
	}
	c.LimitIP = clampDevices(c.LimitIP, agMaxDevices(me))
	c.Reset = 0 // a periodic reset would hand out traffic nobody paid for
	gb := gbOf(c.TotalGB)
	var dur int64
	if c.ExpiryTime > 0 {
		if dur = c.ExpiryTime - now; dur <= 0 {
			fail(w, "the expiry time is in the past")
			return
		}
	}
	user := strings.TrimSpace(c.ID)
	if user == "" {
		user = c.Email
	}
	a.st.mu.RLock()
	why := ""
	for _, id := range s.ids {
		if a.st.st.Inbounds[id] == nil {
			why = "Inbound not found: " + itoa(id)
		}
	}
	if why == "" && a.st.st.Accounts[ekey(c.Email)] != nil {
		why = "Duplicate email: " + c.Email
	}
	if why == "" {
		for _, o := range a.st.st.Accounts {
			if strings.EqualFold(o.Username, user) {
				why = "Duplicate username: " + user
				break
			}
		}
	}
	if why == "" {
		why = a.st.checkSameProtoLocked(s.ids)
	}
	owned, active, today := a.st.countsLocked(me, now)
	if !s.singleSet {
		c.SingleProto = a.st.st.Global.DefaultSingleProto
	}
	svc := a.st.svcLocked(s.ids)
	a.st.mu.RUnlock()
	if why != "" {
		fail(w, why)
		return
	}
	if err := Ag.Check(me, "create", SaleCheck{Owned: owned, Active: active, Today: today, GB: gb, TotalGB: gb, DaysMs: dur,
		Inbounds: s.ids, Devices: c.LimitIP, New: true}); err != nil {
		fail(w, err.Error())
		return
	}
	q := Quote{Kind: "sale", Plan: s.plan, GB: gb, DaysMs: dur}
	if q.Plan == 0 {
		q.Plan = Ag.MatchPlan(gb, dur)
	}
	sale, price, err := Ag.Charge(me, q, ChargeMeta{By: actorOf(r), IP: clientIP(r), Acct: c.Email, Svc: svc})
	if err != nil {
		fail(w, err.Error())
		return
	}
	setClient(r, c)
	setIDs(r, s.ids)
	r.Form.Set("id", itoa(s.ids[0]))
	if x := agCtxOf(r); x != nil {
		x.customer = s.customer
	}
	bw, env := runCore(a.addClient, r)
	if !env.Success {
		Ag.Reverse(sale, "system", "not created: "+env.Msg)
	} else {
		Ag.Log(actorOf(r), "sale", c.Email, clientIP(r), "%s %.2f GB %.2f days, paid %d", svc, gb, float64(dur)/dayMs, price)
		a.agAfterCharge(me, "sale", c.Email, price)
	}
	relay(w, bw)
}

// agUpdateClient is the bot's edit/extend/enable/password change. What is charged is the
// difference: added quota, and time added past max(old expiry, now).
func (a *API) agUpdateClient(w http.ResponseWriter, r *http.Request) {
	agOpMu.Lock()
	defer agOpMu.Unlock()
	me := agentOf(r)
	sub := agSubtree(me)
	target, _ := strconv.Atoi(r.Form.Get("id"))
	ident := r.PathValue("clientId")
	_, present := r.Form["inboundIds"]
	now := nowMs()
	a.st.mu.RLock()
	acc := a.st.findMineLocked(sub, target, ident)
	if acc == nil && present {
		acc = a.st.findMineLocked(sub, 0, ident)
	}
	if acc == nil {
		a.st.mu.RUnlock()
		fail(w, "Client not found")
		return
	}
	old := acc.client()
	oldIDs := append([]int(nil), acc.Inbounds...)
	a.st.mu.RUnlock()
	c, msg := parseClient(r, old)
	if msg != "" {
		fail(w, msg)
		return
	}
	newIDs := oldIDs
	if present {
		newIDs, _ = membership(r, target)
	}
	// fields a reseller never changes through this path
	c.Email, c.Reset, c.SubID = old.Email, old.Reset, old.SubID
	maxDev := agMaxDevices(me)
	c.LimitIP = clampDevices(c.LimitIP, maxDev)
	oldLimit := clampDevices(old.LimitIP, maxDev)

	var perms []string
	need := func(p string) {
		for _, x := range perms {
			if x == p {
				return
			}
		}
		perms = append(perms, p)
	}
	if c.Enable != old.Enable {
		need("suspend")
	}
	if c.Password != old.Password || (strings.TrimSpace(c.ID) != "" && !strings.EqualFold(c.ID, old.ID)) || c.LimitIP != oldLimit ||
		c.SpeedDown != old.SpeedDown || c.SpeedUp != old.SpeedUp || c.SingleProto != old.SingleProto || !sameInts(newIDs, oldIDs) {
		need("edit")
	}
	var addGB float64
	var ext int64
	toUnlimited := false
	switch {
	case c.TotalGB == old.TotalGB:
	case c.TotalGB == 0:
		toUnlimited = true
		need("renew")
	case old.TotalGB == 0 || c.TotalGB < old.TotalGB:
		need("edit") // less quota
	default:
		addGB = gbOf(c.TotalGB - old.TotalGB)
		need("renew")
	}
	switch {
	case c.ExpiryTime == old.ExpiryTime:
	case c.ExpiryTime == 0:
		toUnlimited = true
		need("renew")
	case old.ExpiryTime == 0 || c.ExpiryTime < old.ExpiryTime:
		need("edit") // less time
	default:
		base := max(old.ExpiryTime, now)
		if ext = c.ExpiryTime - base; ext > 0 {
			need("renew")
		} else {
			ext = 0
		}
	}
	if toUnlimited {
		if ag, _ := Ag.Agent(me); !ag.Perms.Unlimited {
			fail(w, "your agency may not sell unlimited quota or time")
			return
		}
	}
	var added []int // only services being added must be ones the agency may sell
	for _, x := range newIDs {
		if !hasInt(oldIDs, x) {
			added = append(added, x)
		}
	}
	for _, p := range perms {
		chk := SaleCheck{Inbounds: added, Devices: c.LimitIP}
		if p == "renew" {
			chk.GB, chk.TotalGB, chk.DaysMs = addGB, gbOf(c.TotalGB), ext
		}
		if p == "suspend" {
			chk = SaleCheck{}
		}
		if err := Ag.Check(me, p, chk); err != nil {
			fail(w, err.Error())
			return
		}
	}
	var sale, price int64
	kind := ""
	if addGB > 0 || ext > 0 {
		q := Quote{GB: addGB, DaysMs: ext, Kind: "renew"}
		switch {
		case addGB > 0 && ext > 0:
			q.Plan = Ag.MatchPlan(addGB, ext)
		case addGB > 0:
			q.Kind = "addgb"
		default:
			q.Kind = "adddays"
		}
		kind = q.Kind
		a.st.mu.RLock()
		svc := a.st.svcLocked(newIDs)
		a.st.mu.RUnlock()
		var err error
		if sale, price, err = Ag.Charge(me, q, ChargeMeta{By: actorOf(r), IP: clientIP(r), Acct: old.Email, Svc: svc}); err != nil {
			fail(w, err.Error())
			return
		}
	}
	setClient(r, c)
	if present {
		setIDs(r, newIDs)
	}
	r.SetPathValue("clientId", old.Email) // unique, unlike a password
	bw, env := runCore(a.updateClient, r)
	if !env.Success {
		Ag.Reverse(sale, "system", "not changed: "+env.Msg)
	} else {
		if kind != "" {
			Ag.Log(actorOf(r), kind, old.Email, clientIP(r), "+%.2f GB +%.2f days, paid %d", addGB, float64(ext)/dayMs, price)
			a.agAfterCharge(me, kind, old.Email, price)
		} else if len(perms) > 0 {
			Ag.Log(actorOf(r), "edit", old.Email, clientIP(r), "%s", strings.Join(perms, ","))
		}
	}
	relay(w, bw)
}

func (a *API) agDelClient(w http.ResponseWriter, r *http.Request) {
	agOpMu.Lock()
	defer agOpMu.Unlock()
	me := agentOf(r)
	sub := agSubtree(me)
	id := pathID(r)
	pv := "clientId"
	ident := r.PathValue("clientId")
	if ident == "" {
		pv, ident = "email", r.PathValue("email")
	}
	a.st.mu.RLock()
	acc := a.st.findMineLocked(sub, id, ident)
	var email string
	var created, used, total, expiry int64
	gone := false
	if acc != nil {
		email, created, used, total, expiry = acc.Email, acc.CreatedAt, acc.Up+acc.Down, acc.TotalGB, acc.ExpiryTime
		gone = len(delInt(append([]int(nil), acc.Inbounds...), id)) == 0
	}
	a.st.mu.RUnlock()
	if acc == nil {
		fail(w, "Client not found")
		return
	}
	if err := Ag.Check(me, "delete", SaleCheck{}); err != nil {
		fail(w, err.Error())
		return
	}
	r.SetPathValue(pv, email)
	bw, env := runCore(a.delClient, r)
	if env.Success && gone {
		back := Ag.Refund(email, created, used, total, expiry, actorOf(r))
		Ag.Log(actorOf(r), "delete", email, clientIP(r), "refund %d", back)
	}
	relay(w, bw)
}

func (a *API) agResetTraffic(w http.ResponseWriter, r *http.Request) {
	agOpMu.Lock()
	defer agOpMu.Unlock()
	a.agResetCore(w, r)
}

// agResetCore charges the used traffic and resets it. Callers hold agOpMu.
func (a *API) agResetCore(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	sub := agSubtree(me)
	email := r.PathValue("email")
	a.st.mu.RLock()
	acc := a.st.st.Accounts[ekey(email)]
	var used, total int64
	var svc string
	if mine(sub, acc) {
		used, total, email = acc.Up+acc.Down, acc.TotalGB, acc.Email
		svc = a.st.svcLocked(acc.Inbounds)
	} else {
		acc = nil
	}
	a.st.mu.RUnlock()
	if acc == nil {
		fail(w, "Client not found")
		return
	}
	charge := min(used, total) // an unlimited account (total 0) costs nothing to reset
	if err := Ag.Check(me, "reset", SaleCheck{GB: gbOf(charge)}); err != nil {
		fail(w, err.Error())
		return
	}
	var sale, price int64
	if charge > 0 {
		var err error
		if sale, price, err = Ag.Charge(me, Quote{Kind: "reset", GB: gbOf(charge)}, ChargeMeta{By: actorOf(r), IP: clientIP(r), Acct: email, Svc: svc}); err != nil {
			fail(w, err.Error())
			return
		}
	}
	r.SetPathValue("email", email)
	bw, env := runCore(a.resetTraffic, r)
	if !env.Success {
		Ag.Reverse(sale, "system", "not reset: "+env.Msg)
	} else {
		Ag.Log(actorOf(r), "reset", email, clientIP(r), "%.2f GB, paid %d", gbOf(charge), price)
		a.agAfterCharge(me, "reset", email, price)
	}
	relay(w, bw)
}

func (a *API) agDelDepleted(w http.ResponseWriter, r *http.Request) {
	agOpMu.Lock()
	defer agOpMu.Unlock()
	me := agentOf(r)
	if err := Ag.Check(me, "delete", SaleCheck{}); err != nil {
		fail(w, err.Error())
		return
	}
	sub := agSubtree(me)
	id := pathID(r)
	now := nowMs()
	var gone []string
	var reload []int
	a.st.mu.Lock()
	for k, acc := range a.st.st.Accounts {
		if mine(sub, acc) && (id == 0 || hasInt(acc.Inbounds, id)) && (acc.expired(now) || acc.overQuota()) {
			gone = append(gone, acc.Email)
			reload = append(reload, acc.Inbounds...)
			delete(a.st.st.Accounts, k)
		}
	}
	if len(gone) > 0 {
		a.st.touch()
	}
	a.st.mu.Unlock()
	for _, e := range gone {
		a.d.Kick(e)
	}
	for _, x := range unionInts(reload, nil) {
		a.d.ReloadInbound(x)
	}
	if len(gone) > 0 {
		Ag.Log(actorOf(r), "delete", "", clientIP(r), "%d depleted accounts", len(gone))
	}
	ok(w, "Depleted clients deleted", len(gone))
}

// agAfterCharge sends the notices a charge may call for (a low wallet, a sale for the admin).
func (a *API) agAfterCharge(me int, kind, acct string, price int64) {
	Ag.mu.RLock()
	set := Ag.f.Settings
	var low []*Agent
	var who string
	for _, x := range Ag.chainLocked(me) {
		if set.LowBalance > 0 && Ag.bal[x.ID] < set.LowBalance {
			cp := *x
			low = append(low, &cp)
		}
	}
	if x := Ag.agentLocked(me); x != nil {
		who = x.Username
	}
	bals := map[int]int64{}
	for _, x := range low {
		bals[x.ID] = Ag.bal[x.ID]
	}
	Ag.mu.RUnlock()
	if set.NotifySale && price > 0 {
		a.st.TgNotify(fmt.Sprintf("🛒 %s: %s %s (%d %s)", who, kind, acct, price, set.Currency))
	}
	for _, x := range low {
		if !lowNoticeDue(x.ID) {
			continue
		}
		text := fmt.Sprintf("⚠️ کیف پول نمایندگی %s کم است: %d %s", x.Username, bals[x.ID], set.Currency)
		a.st.TgNotify(text)
		if x.TgChat != "" {
			a.st.TgSend(x.TgChat, text)
		}
	}
}

var lowNotice = struct {
	sync.Mutex
	m map[int]int64
}{m: map[int]int64{}}

func lowNoticeDue(id int) bool {
	lowNotice.Lock()
	defer lowNotice.Unlock()
	if nowMs()-lowNotice.m[id] < 6*3600000 {
		return false
	}
	lowNotice.m[id] = nowMs()
	return true
}

// ---------------------------------------------------------------- reseller page endpoints (/panel/ui)

func (a *API) agPassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Old, New string }
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.New) < 6 {
		fail(w, "new password must be at least 6 characters")
		return
	}
	if agCtxOf(r).via == "api" {
		fail(w, "not available through the API")
		return
	}
	me := agentOf(r)
	ag, _ := Ag.Agent(me)
	if x, _ := Ag.Authenticate(ag.Username, req.Old); x == nil || x.ID != me {
		fail(w, "current password is wrong")
		return
	}
	Ag.mu.Lock()
	x := Ag.agentLocked(me)
	x.Hash = hashPass(randHex(8), req.New)
	x.TokenVer++
	ver := x.TokenVer
	err := Ag.saveLocked()
	Ag.logLocked(actorOf(r), "password", "agent:"+itoa(me), clientIP(r), "own password changed")
	Ag.mu.Unlock()
	if err != nil {
		fail(w, err.Error())
		return
	}
	a.st.issueAgent(w, me, ver, r.TLS != nil)
	ok(w, "password changed", nil)
}

// agBulk is the account page's bulk action for a reseller: every account is charged on its own.
func (a *API) agBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string   `json:"action"`
		Emails []string `json:"emails"`
		Days   float64  `json:"days"`
		Hours  float64  `json:"hours"`
		GB     float64  `json:"gb"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Emails) == 0 {
		fail(w, "bad request")
		return
	}
	agOpMu.Lock()
	defer agOpMu.Unlock()
	me := agentOf(r)
	if len(req.Emails) > 1 {
		if err := Ag.Check(me, "bulk", SaleCheck{}); err != nil {
			fail(w, err.Error())
			return
		}
	}
	sub := agSubtree(me)
	n := 0
	var firstErr string
	note := func(err error) {
		if err != nil && firstErr == "" {
			firstErr = err.Error()
		}
	}
	switch req.Action {
	case "enable", "disable":
		if err := Ag.Check(me, "suspend", SaleCheck{}); err != nil {
			fail(w, err.Error())
			return
		}
		var kick []string
		a.st.mu.Lock()
		for _, e := range req.Emails {
			if acc := a.st.st.Accounts[ekey(e)]; mine(sub, acc) {
				acc.Enable = req.Action == "enable"
				if !acc.Enable {
					kick = append(kick, acc.Email)
				}
				n++
			}
		}
		a.st.touch()
		a.st.mu.Unlock()
		for _, e := range kick {
			a.d.Kick(e)
		}
		Ag.Log(actorOf(r), req.Action, "", clientIP(r), "%d accounts", n)
	case "reset":
		for _, e := range req.Emails {
			rr := r.Clone(r.Context())
			rr.Form = url.Values{}
			rr.SetPathValue("email", e)
			bw := &bufWriter{h: http.Header{}}
			a.agResetCore(bw, rr)
			var env envelope
			json.Unmarshal(bw.buf.Bytes(), &env)
			if env.Success {
				n++
			} else {
				note(errors.New(e + ": " + env.Msg))
			}
		}
	case "extend":
		dur := int64((req.Days*24 + req.Hours) * 3600000)
		for _, e := range req.Emails {
			if _, err := a.agRenew(r, me, sub, renewReq{Email: e, GB: req.GB, DaysMs: dur}); err != nil {
				note(errors.New(e + ": " + err.Error()))
			} else {
				n++
			}
		}
	case "delete":
		if err := Ag.Check(me, "delete", SaleCheck{}); err != nil {
			fail(w, err.Error())
			return
		}
		type del struct {
			email                        string
			created, used, total, expiry int64
		}
		var dels []del
		var reload []int
		a.st.mu.Lock()
		for _, e := range req.Emails {
			if acc := a.st.st.Accounts[ekey(e)]; mine(sub, acc) {
				dels = append(dels, del{acc.Email, acc.CreatedAt, acc.Up + acc.Down, acc.TotalGB, acc.ExpiryTime})
				reload = append(reload, acc.Inbounds...)
				delete(a.st.st.Accounts, ekey(e))
			}
		}
		a.st.touch()
		a.st.mu.Unlock()
		for _, d := range dels {
			a.d.Kick(d.email)
			back := Ag.Refund(d.email, d.created, d.used, d.total, d.expiry, actorOf(r))
			Ag.Log(actorOf(r), "delete", d.email, clientIP(r), "refund %d", back)
			n++
		}
		for _, id := range unionInts(reload, nil) {
			a.d.ReloadInbound(id)
		}
	default:
		fail(w, "unknown action")
		return
	}
	if firstErr != "" {
		writeJSON(w, envelope{n > 0, fmt.Sprintf("%d done; %s", n, firstErr), n})
		return
	}
	ok(w, "done", n)
}

type renewReq struct {
	Email  string
	Plan   int     // renew with a plan (its quota and time, at its renewal price)
	GB     float64 // or a custom amount of quota ...
	DaysMs int64   // ... and time
	Fresh  bool    // start a new period: quota = GB, used traffic back to 0 (otherwise quota is added)
}

// agRenew adds time and quota to one of the caller's accounts and charges for it. Callers hold agOpMu.
func (a *API) agRenew(r *http.Request, me int, sub map[int]bool, q renewReq) (int64, error) {
	now := nowMs()
	if q.Plan > 0 {
		Ag.mu.RLock()
		p := Ag.f.Plans[itoa(q.Plan)]
		var pc Plan
		if p != nil {
			pc = *p
		}
		Ag.mu.RUnlock()
		if p == nil || !pc.Enable {
			return 0, errors.New("plan not found")
		}
		q.GB, q.DaysMs = pc.GB, int64(math.Round(pc.Days*dayMs))
	}
	if q.GB < 0 || q.DaysMs < 0 || (q.GB == 0 && q.DaysMs == 0 && !q.Fresh) {
		return 0, errors.New("nothing to add")
	}
	a.st.mu.RLock()
	acc := a.st.st.Accounts[ekey(q.Email)]
	if !mine(sub, acc) {
		a.st.mu.RUnlock()
		return 0, errors.New("account not found")
	}
	email, total, inbounds := acc.Email, acc.TotalGB, append([]int(nil), acc.Inbounds...)
	unlimitedTime := acc.ExpiryTime == 0
	svc := a.st.svcLocked(inbounds)
	a.st.mu.RUnlock()
	if unlimitedTime { // nothing to add to unlimited time
		q.DaysMs = 0
	}
	addGB := q.GB
	newTotal := gbOf(total) + q.GB
	if q.Fresh {
		newTotal = q.GB
	}
	if total == 0 && !q.Fresh { // unlimited quota: nothing to add
		addGB, newTotal = 0, 0
	}
	if q.Fresh && q.GB == 0 {
		if ag, _ := Ag.Agent(me); !ag.Perms.Unlimited {
			return 0, errors.New("your agency may not sell unlimited quota or time")
		}
	}
	if addGB == 0 && q.DaysMs == 0 && !q.Fresh {
		return 0, errors.New("nothing to add (unlimited account)")
	}
	if err := Ag.Check(me, "renew", SaleCheck{GB: addGB, TotalGB: newTotal, DaysMs: q.DaysMs}); err != nil {
		return 0, err
	}
	qt := Quote{Kind: "renew", Plan: q.Plan, GB: addGB, DaysMs: q.DaysMs}
	if q.Plan == 0 {
		switch {
		case addGB > 0 && q.DaysMs > 0:
			qt.Plan = Ag.MatchPlan(addGB, q.DaysMs)
		case addGB > 0:
			qt.Kind = "addgb"
		default:
			qt.Kind = "adddays"
		}
	}
	sale, price, err := Ag.Charge(me, qt, ChargeMeta{By: actorOf(r), IP: clientIP(r), Acct: email, Svc: svc})
	if err != nil {
		return 0, err
	}
	a.st.mu.Lock()
	acc = a.st.st.Accounts[ekey(email)]
	if !mine(sub, acc) {
		a.st.mu.Unlock()
		Ag.Reverse(sale, "system", "account vanished")
		return 0, errors.New("account not found")
	}
	if q.DaysMs > 0 && acc.ExpiryTime > 0 {
		acc.ExpiryTime = max(acc.ExpiryTime, now) + q.DaysMs
	}
	if q.Fresh {
		acc.TotalGB = int64(math.Round(q.GB * gib))
		acc.Up, acc.Down = 0, 0
	} else if addGB > 0 && acc.TotalGB > 0 {
		acc.TotalGB += int64(math.Round(addGB * gib))
	}
	a.st.touch()
	a.st.mu.Unlock()
	for _, id := range inbounds {
		a.d.ReloadInbound(id)
	}
	Ag.Log(actorOf(r), qt.Kind, email, clientIP(r), "+%.2f GB +%.2f days fresh=%v, paid %d", addGB, float64(q.DaysMs)/dayMs, q.Fresh, price)
	a.agAfterCharge(me, qt.Kind, email, price)
	return price, nil
}

func (a *API) agBulkCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prefix    string  `json:"prefix"`
		Count     int     `json:"count"`
		Inbounds  []int   `json:"inbounds"`
		Plan      int     `json:"plan"`
		GB        float64 `json:"gb"`
		Days      float64 `json:"days"`
		Hours     float64 `json:"hours"`
		LimitIP   int     `json:"limitIp"`
		SpeedDown int     `json:"speedDown"`
		SpeedUp   int     `json:"speedUp"`
		PassLen   int     `json:"passLen"`
		Single    bool    `json:"singleProto"`
		Customer  int     `json:"customer"`
		Comment   string  `json:"comment"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Count < 1 || req.Count > 200 {
		fail(w, "bad request (1 to 200 accounts at a time)")
		return
	}
	agOpMu.Lock()
	defer agOpMu.Unlock()
	me := agentOf(r)
	if req.Count > 1 {
		if err := Ag.Check(me, "bulk", SaleCheck{}); err != nil {
			fail(w, err.Error())
			return
		}
	}
	if req.Plan > 0 {
		Ag.mu.RLock()
		p := Ag.f.Plans[itoa(req.Plan)]
		var pc Plan
		if p != nil {
			pc = *p
		}
		Ag.mu.RUnlock()
		if p == nil || !pc.Enable {
			fail(w, "plan not found")
			return
		}
		req.GB, req.Days, req.Hours = pc.GB, pc.Days, 0
		if pc.Devices > 0 && req.LimitIP == 0 {
			req.LimitIP = pc.Devices
		}
		if len(pc.Inbounds) > 0 && len(req.Inbounds) == 0 {
			req.Inbounds = pc.Inbounds
		}
	}
	if len(req.Inbounds) == 0 {
		fail(w, "choose at least one service")
		return
	}
	if req.Customer > 0 && !agOwnsCustomer(me, req.Customer) {
		fail(w, "customer not found")
		return
	}
	if req.PassLen < 6 {
		req.PassLen = 10
	}
	prefix := strings.TrimSpace(req.Prefix)
	if prefix == "" {
		prefix = "u"
	}
	type made struct{ User, Pass string }
	var out []made
	var stop string
	dur := int64(math.Round((req.Days*24 + req.Hours) * 3600000))
	for i, tries := 1, 0; len(out) < req.Count && tries < 100000; i++ {
		tries++
		name := fmt.Sprintf("%s%d", prefix, i)
		a.st.mu.RLock()
		taken := a.st.st.Accounts[ekey(name)] != nil
		if !taken {
			for _, o := range a.st.st.Accounts {
				if strings.EqualFold(o.Username, name) {
					taken = true
					break
				}
			}
		}
		a.st.mu.RUnlock()
		if taken {
			continue
		}
		c := clientJSON{ID: name, Email: name, Password: randPass(req.PassLen), Enable: true, LimitIP: req.LimitIP,
			TotalGB: int64(math.Round(req.GB * gib)), SpeedDown: req.SpeedDown, SpeedUp: req.SpeedUp,
			SingleProto: req.Single, Comment: req.Comment, SubID: newSubID()}
		if dur > 0 {
			c.ExpiryTime = nowMs() + dur
		}
		rr := r.Clone(r.Context())
		rr.Form = url.Values{}
		bw := &bufWriter{h: http.Header{}}
		a.agCreate(bw, rr, sellSpec{c: c, ids: req.Inbounds, plan: req.Plan, customer: req.Customer, singleSet: true})
		var env envelope
		json.Unmarshal(bw.buf.Bytes(), &env)
		if !env.Success {
			if strings.HasPrefix(env.Msg, "Duplicate") {
				continue
			}
			stop = env.Msg
			break
		}
		out = append(out, made{name, c.Password})
	}
	if stop != "" {
		writeJSON(w, envelope{len(out) > 0, fmt.Sprintf("%d created; stopped: %s", len(out), stop), out})
		return
	}
	ok(w, "created", out)
}

// ---------------------------------------------------------------- agency endpoints

const (
	roleAny = iota
	roleAdmin
	roleAgent
	roleManager // the admin, or an agent allowed to have sub-agents
)

func (a *API) agencyGuard(role int, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, via, okk := a.identify(w, r)
		if !okk {
			if via != "handled" {
				w.WriteHeader(http.StatusUnauthorized)
				writeJSON(w, envelope{false, "login required", nil})
			}
			return
		}
		if Ag == nil {
			fail(w, "the agency module is not available (see the panel log)")
			return
		}
		r.ParseForm()
		if id > 0 {
			r = withAgent(r, id, via)
		}
		switch role {
		case roleAdmin:
			if id != 0 {
				w.WriteHeader(http.StatusForbidden)
				writeJSON(w, envelope{false, "admin only", nil})
				return
			}
		case roleAgent:
			if id == 0 {
				fail(w, "this is done from an agency account")
				return
			}
		case roleManager:
			if id != 0 {
				if ag, _ := Ag.Agent(id); !ag.Perms.SubAgents {
					w.WriteHeader(http.StatusForbidden)
					writeJSON(w, envelope{false, "your agency may not manage sub-agents", nil})
					return
				}
			}
		}
		h(w, r)
	}
}

func (a *API) agencyRoutes(mux *http.ServeMux) {
	rt := func(m, p string, role int, h http.HandlerFunc) {
		mux.HandleFunc(m+" /panel/agency"+p, a.agencyGuard(role, h))
	}
	rt("GET", "/whoami", roleAny, a.agWhoami)
	rt("GET", "/dashboard", roleAny, a.agDashboard)
	rt("GET", "/plans", roleAny, a.agPlans)
	rt("POST", "/plans/save", roleAdmin, a.agPlanSave)
	rt("POST", "/plans/del", roleAdmin, a.agPlanDel)
	rt("GET", "/settings", roleAdmin, a.agSettingsGet)
	rt("POST", "/settings", roleAdmin, a.agSettingsSet)
	rt("POST", "/quote", roleAny, a.agQuote)
	rt("POST", "/sell", roleAgent, a.agSell)
	rt("POST", "/renew", roleAgent, a.agRenewHTTP)

	rt("GET", "/agents", roleManager, a.agAgents)
	rt("POST", "/agents/save", roleManager, a.agAgentSave)
	rt("POST", "/agents/{id}/wallet", roleManager, a.agWallet)
	rt("POST", "/agents/{id}/ban", roleManager, a.agBan)
	rt("POST", "/agents/{id}/freeze", roleManager, a.agFreeze)
	rt("POST", "/agents/{id}/delete", roleManager, a.agAgentDelete)
	rt("POST", "/agents/{id}/move", roleAdmin, a.agAgentMove)
	rt("POST", "/agents/{id}/login", roleAdmin, a.agImpersonate)
	rt("POST", "/transfer", roleAdmin, a.agTransfer)
	rt("POST", "/back", roleAny, a.agBack)

	rt("GET", "/ledger", roleAny, a.agLedger)
	rt("GET", "/activity", roleAny, a.agActivity)
	rt("GET", "/reports", roleAny, a.agReports)
	rt("GET", "/apilog", roleAny, a.agAPILog)

	rt("GET", "/customers", roleAny, a.agCustomers)
	rt("POST", "/customers/save", roleAny, a.agCustomerSave)
	rt("POST", "/customers/del", roleAny, a.agCustomerDel)
	rt("POST", "/accounts/customer", roleAny, a.agSetCustomer)
	rt("POST", "/accounts/move", roleAny, a.agMoveAccounts)
	rt("GET", "/requests", roleAny, a.agRequests)
	rt("POST", "/requests/decide", roleAdmin, a.agRequestDecide)

	rt("GET", "/keys", roleAny, a.agKeys)
	rt("POST", "/keys/new", roleAny, a.agKeyNew)
	rt("POST", "/keys/del", roleAny, a.agKeyDel)
	rt("POST", "/keys/allow", roleAny, a.agKeyAllow)
	rt("POST", "/password", roleAgent, a.agPassword)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(v)
}

// agentPublic is an agent without its secrets.
func agentPublic(x *Agent) Agent {
	cp := *x
	cp.Hash = ""
	cp.APIKeys = make([]APIKey, len(x.APIKeys))
	for i, k := range x.APIKeys {
		k.Hash = ""
		cp.APIKeys[i] = k
	}
	cp.Pricing.Plans = map[string]PlanPrice{}
	for k, v := range x.Pricing.Plans {
		cp.Pricing.Plans[k] = v
	}
	cp.Limits.Inbounds = append([]int(nil), x.Limits.Inbounds...)
	cp.APIAllow = append([]string(nil), x.APIAllow...)
	return cp
}

func agStatus(x *Agent, now int64) string {
	switch {
	case !x.Enable:
		return "disabled"
	case x.BanUntil == -1 || x.BanUntil > now:
		return "banned"
	case x.Expiry > 0 && x.Expiry <= now:
		return "expired"
	}
	return "active"
}

// manages: may the caller (me, 0 = admin) manage agent id? Only agents strictly below it.
func (ag *AgencyStore) managesLocked(me, id int) bool {
	x := ag.agentLocked(id)
	if x == nil || id == me {
		return false
	}
	return me == 0 || ag.isUnderLocked(id, me)
}

func (a *API) agWhoami(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	Ag.mu.RLock()
	set := Ag.f.Settings
	out := map[string]any{"currency": set.Currency, "maxLevels": set.MaxLevels, "version": version}
	if me == 0 {
		out["role"] = "admin"
		pending := 0
		for _, q := range Ag.f.Requests {
			if q.Status == "pending" {
				pending++
			}
		}
		out["pendingRequests"] = pending
		out["agents"] = len(Ag.f.Agents)
	} else {
		x := Ag.agentLocked(me)
		pub := agentPublic(x)
		out["role"] = "agent"
		out["agent"] = pub
		out["balance"] = Ag.bal[me]
		out["level"] = Ag.levelLocked(me)
		out["prices"] = Ag.effPricesLocked(me)
		allow := Ag.allowedInboundsLocked(me)
		var ins []int
		for id := range allow {
			ins = append(ins, id)
		}
		sort.Ints(ins)
		out["inbounds"] = ins // nil = every service
		out["canSub"] = x.Perms.SubAgents && Ag.levelLocked(me) < set.MaxLevels
		out["impersonated"] = agCtxOf(r).via == "imp"
	}
	Ag.mu.RUnlock()
	// services the caller may sell, for the forms
	allow := map[int]bool(nil)
	if me > 0 {
		allow = agAllowed(me)
	}
	type svc struct {
		ID       int    `json:"id"`
		Remark   string `json:"remark"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Enable   bool   `json:"enable"`
		Domain   string `json:"domain"`
		PSK      string `json:"psk,omitempty"`
	}
	var svcs []svc
	a.st.mu.RLock()
	for _, in := range a.st.sortedInbounds() {
		if allow == nil || allow[in.ID] {
			svcs = append(svcs, svc{in.ID, in.Remark, in.Protocol, in.Port, in.Enable, strings.TrimSpace(strSetting(in.Settings, "connDomain", "")), l2tpPSK(in)})
		}
	}
	a.st.mu.RUnlock()
	out["services"] = svcs
	ok(w, "", out)
}

// ---------------------------------------------------------------- plans and settings

type planOut struct {
	Plan
	MyPrice int64 `json:"myPrice"`
	MyRenew int64 `json:"myRenew"`
}

func (a *API) agPlans(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	Ag.mu.RLock()
	var out []planOut
	for _, p := range Ag.f.Plans {
		if me > 0 && !p.Enable {
			continue
		}
		po := planOut{Plan: *p}
		po.Inbounds = append([]int(nil), p.Inbounds...)
		if me > 0 {
			po.MyPrice, _ = Ag.priceLocked(me, Quote{Kind: "sale", Plan: p.ID})
			po.MyRenew, _ = Ag.priceLocked(me, Quote{Kind: "renew", Plan: p.ID})
		} else {
			po.MyPrice, po.MyRenew = p.Price, p.Price
			if p.Renew > 0 {
				po.MyRenew = p.Renew
			}
		}
		out = append(out, po)
	}
	Ag.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	ok(w, "", out)
}

func (a *API) agPlanSave(w http.ResponseWriter, r *http.Request) {
	var p Plan
	if readJSON(r, &p) != nil || strings.TrimSpace(p.Name) == "" || p.GB < 0 || p.Days < 0 || p.Price < 0 || p.Renew < 0 {
		fail(w, "name, quota, days and price are required")
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	if p.ID == 0 {
		p.ID = Ag.f.NextPlan
		Ag.f.NextPlan++
	} else if Ag.f.Plans[itoa(p.ID)] == nil {
		fail(w, "plan not found")
		return
	}
	old := Ag.f.Plans[itoa(p.ID)]
	Ag.f.Plans[itoa(p.ID)] = &p
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	detail := fmt.Sprintf("%s %.2fGB %.2fd price %d renew %d", p.Name, p.GB, p.Days, p.Price, p.Renew)
	if old != nil && (old.Price != p.Price || old.Renew != p.Renew) {
		detail += fmt.Sprintf(" (was %d / %d)", old.Price, old.Renew)
	}
	Ag.logLocked(actorOf(r), "plan:save", "plan:"+itoa(p.ID), clientIP(r), "%s", detail)
	ok(w, "saved", p)
}

func (a *API) agPlanDel(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID int }
	readJSON(r, &req)
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	if Ag.f.Plans[itoa(req.ID)] == nil {
		fail(w, "plan not found")
		return
	}
	delete(Ag.f.Plans, itoa(req.ID))
	for _, x := range Ag.f.Agents {
		delete(x.Pricing.Plans, itoa(req.ID))
	}
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	Ag.logLocked(actorOf(r), "plan:delete", "plan:"+itoa(req.ID), clientIP(r), "")
	ok(w, "deleted", nil)
}

func (a *API) agSettingsGet(w http.ResponseWriter, r *http.Request) {
	Ag.mu.RLock()
	s := Ag.f.Settings
	Ag.mu.RUnlock()
	ok(w, "", s)
}

func (a *API) agSettingsSet(w http.ResponseWriter, r *http.Request) {
	var s AgencySettings
	if readJSON(r, &s) != nil {
		fail(w, "bad request")
		return
	}
	if s.MaxLevels < 1 || s.MaxLevels > 10 {
		fail(w, "levels must be 1 to 10")
		return
	}
	switch s.Refund.Mode {
	case "none", "window", "prorated":
	default:
		fail(w, "refund mode must be none, window or prorated")
		return
	}
	if s.Refund.Percent < 0 || s.Refund.Percent > 100 || s.PerGB < 0 || s.PerDay < 0 || s.AddGB < 0 || s.AddDay < 0 {
		fail(w, "invalid value")
		return
	}
	if strings.TrimSpace(s.Currency) == "" {
		s.Currency = "تومان"
	}
	Ag.mu.Lock()
	old := Ag.f.Settings
	Ag.f.Settings = s
	err := Ag.saveLocked()
	if err == nil {
		Ag.logLocked(actorOf(r), "settings", "", clientIP(r), "base prices GB %d→%d day %d→%d addGB %d→%d addDay %d→%d refund %s %d%%",
			old.PerGB, s.PerGB, old.PerDay, s.PerDay, old.AddGB, s.AddGB, old.AddDay, s.AddDay, s.Refund.Mode, s.Refund.Percent)
	}
	Ag.mu.Unlock()
	if err != nil {
		fail(w, err.Error())
		return
	}
	ok(w, "saved", nil)
}

type quoteReq struct {
	Kind  string  `json:"kind"`
	Plan  int     `json:"plan"`
	GB    float64 `json:"gb"`
	Days  float64 `json:"days"`
	Hours float64 `json:"hours"`
	Agent int     `json:"agent"` // a manager may price for one of its agents
}

func (q quoteReq) quote() Quote {
	k := q.Kind
	if k == "" {
		k = "sale"
	}
	return Quote{Kind: k, Plan: q.Plan, GB: q.GB, DaysMs: int64(math.Round((q.Days*24 + q.Hours) * 3600000))}
}

func (a *API) agQuote(w http.ResponseWriter, r *http.Request) {
	var req quoteReq
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	me := agentOf(r)
	who := me
	Ag.mu.RLock()
	defer Ag.mu.RUnlock()
	if req.Agent > 0 && req.Agent != me {
		if !Ag.managesLocked(me, req.Agent) {
			fail(w, "agent not found")
			return
		}
		who = req.Agent
	}
	if who == 0 {
		fail(w, "choose an agency")
		return
	}
	q := req.quote()
	if q.Plan > 0 {
		if p := Ag.f.Plans[itoa(q.Plan)]; p != nil {
			q.GB, q.DaysMs = p.GB, int64(math.Round(p.Days*dayMs))
		}
	}
	price, err := Ag.priceLocked(who, q)
	if err != nil {
		fail(w, err.Error())
		return
	}
	ok(w, "", map[string]any{"price": price, "balance": Ag.bal[who], "currency": Ag.f.Settings.Currency})
}

// agSell is the agency page's "new account" for a reseller.
func (a *API) agSell(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string  `json:"username"`
		Password  string  `json:"password"`
		Plan      int     `json:"plan"`
		GB        float64 `json:"gb"`
		Days      float64 `json:"days"`
		Hours     float64 `json:"hours"`
		Inbounds  []int   `json:"inbounds"`
		LimitIP   int     `json:"limitIp"`
		Customer  int     `json:"customer"`
		Comment   string  `json:"comment"`
		Single    *bool   `json:"singleProto"`
		SpeedDown int     `json:"speedDown"`
		SpeedUp   int     `json:"speedUp"`
	}
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	me := agentOf(r)
	name := strings.TrimSpace(req.Username)
	if name == "" || strings.ContainsAny(name, " /\\\"'") {
		fail(w, "a username without spaces is required")
		return
	}
	if req.Password == "" {
		req.Password = randPass(10)
	}
	if req.Customer > 0 && !agOwnsCustomer(me, req.Customer) {
		fail(w, "customer not found")
		return
	}
	if req.Plan > 0 {
		Ag.mu.RLock()
		p := Ag.f.Plans[itoa(req.Plan)]
		var pc Plan
		if p != nil {
			pc = *p
		}
		Ag.mu.RUnlock()
		if p == nil || !pc.Enable {
			fail(w, "plan not found")
			return
		}
		req.GB, req.Days, req.Hours = pc.GB, pc.Days, 0
		if req.LimitIP == 0 {
			req.LimitIP = pc.Devices
		}
		if len(req.Inbounds) == 0 {
			req.Inbounds = pc.Inbounds
		}
	}
	c := clientJSON{ID: name, Email: name, Password: req.Password, Enable: true, LimitIP: req.LimitIP,
		TotalGB: int64(math.Round(req.GB * gib)), Comment: req.Comment, SubID: newSubID(), SpeedDown: req.SpeedDown, SpeedUp: req.SpeedUp}
	if d := int64(math.Round((req.Days*24 + req.Hours) * 3600000)); d > 0 {
		c.ExpiryTime = nowMs() + d
	}
	spec := sellSpec{c: c, ids: unionInts(req.Inbounds, nil), plan: req.Plan, customer: req.Customer}
	if req.Single != nil {
		spec.c.SingleProto, spec.singleSet = *req.Single, true
	}
	agOpMu.Lock()
	defer agOpMu.Unlock()
	bw := &bufWriter{h: http.Header{}}
	a.agCreate(bw, r, spec)
	var env envelope
	json.Unmarshal(bw.buf.Bytes(), &env)
	if !env.Success {
		fail(w, env.Msg)
		return
	}
	ok(w, "created", map[string]any{"username": name, "password": c.Password, "balance": Ag.Balance(me)})
}

func (a *API) agRenewHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Emails []string `json:"emails"`
		Plan   int      `json:"plan"`
		GB     float64  `json:"gb"`
		Days   float64  `json:"days"`
		Hours  float64  `json:"hours"`
		Fresh  bool     `json:"fresh"`
	}
	if readJSON(r, &req) != nil || len(req.Emails) == 0 {
		fail(w, "bad request")
		return
	}
	agOpMu.Lock()
	defer agOpMu.Unlock()
	me := agentOf(r)
	if len(req.Emails) > 1 {
		if err := Ag.Check(me, "bulk", SaleCheck{}); err != nil {
			fail(w, err.Error())
			return
		}
	}
	sub := agSubtree(me)
	n := 0
	var total int64
	for _, e := range req.Emails {
		p, err := a.agRenew(r, me, sub, renewReq{Email: e, Plan: req.Plan, GB: req.GB,
			DaysMs: int64(math.Round((req.Days*24 + req.Hours) * 3600000)), Fresh: req.Fresh})
		if err != nil {
			writeJSON(w, envelope{n > 0, fmt.Sprintf("%d renewed; %s: %s", n, e, err.Error()), n})
			return
		}
		n++
		total += p
	}
	ok(w, fmt.Sprintf("%d renewed, paid %d", n, total), map[string]any{"count": n, "paid": total, "balance": Ag.Balance(me)})
}

// ---------------------------------------------------------------- agents

type agentRow struct {
	Agent
	Balance    int64     `json:"balance"`
	Level      int       `json:"level"`
	Status     string    `json:"status"`
	ParentName string    `json:"parentName"`
	Children   int       `json:"children"`
	Accounts   int       `json:"accounts"`
	Active     int       `json:"active"`
	Online     int       `json:"online"`
	Used       int64     `json:"used"`       // traffic used by its accounts
	SalesMonth int       `json:"salesMonth"` // own sales and renewals in 30 days
	PaidMonth  int64     `json:"paidMonth"`  // what it paid for them
	LastSale   int64     `json:"lastSale"`
	Eff        pricesEff `json:"eff"`
}

func (a *API) agAgents(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	now := nowMs()
	type cnt struct {
		n, active, online int
		used              int64
	}
	counts := map[int]*cnt{}
	on := onlineCounts()
	a.st.mu.RLock()
	for _, acc := range a.st.st.Accounts {
		if acc.Owner == 0 {
			continue
		}
		c := counts[acc.Owner]
		if c == nil {
			c = &cnt{}
			counts[acc.Owner] = c
		}
		c.n++
		c.used += acc.Up + acc.Down
		if statusOf(acc, now) == "active" {
			c.active++
		}
		if on[strings.ToLower(acc.Email)] > 0 {
			c.online++
		}
	}
	a.st.mu.RUnlock()
	Ag.mu.RLock()
	var rows []agentRow
	month := now - 30*dayMs
	sales := map[int]int{}
	paid := map[int]int64{}
	last := map[int]int64{}
	for _, e := range Ag.ledger {
		if e.Sale == 0 || e.Agent != e.Seller {
			continue
		}
		if chargeKinds[e.Kind] && e.T > last[e.Agent] {
			last[e.Agent] = e.T
		}
		if e.T >= month {
			if chargeKinds[e.Kind] {
				sales[e.Agent]++
			}
			paid[e.Agent] -= e.Amt
		}
	}
	for _, x := range Ag.f.Agents {
		if !Ag.managesLocked(me, x.ID) {
			continue
		}
		row := agentRow{Agent: agentPublic(x), Balance: Ag.bal[x.ID], Level: Ag.levelLocked(x.ID), Status: agStatus(x, now),
			Children: len(Ag.childrenLocked(x.ID)), SalesMonth: sales[x.ID], PaidMonth: paid[x.ID], LastSale: last[x.ID],
			Eff: Ag.effPricesLocked(x.ID)}
		if p := Ag.agentLocked(x.Parent); p != nil {
			row.ParentName = p.Username
		}
		if c := counts[x.ID]; c != nil {
			row.Accounts, row.Active, row.Online, row.Used = c.n, c.active, c.online, c.used
		}
		rows = append(rows, row)
	}
	Ag.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if rows == nil {
		rows = []agentRow{}
	}
	ok(w, "", rows)
}

func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

type agentSave struct {
	Agent
	Password string `json:"password"`
}

func (a *API) agAgentSave(w http.ResponseWriter, r *http.Request) {
	var req agentSave
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	me := agentOf(r)
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername(req.Username) {
		fail(w, "username: 3-32 letters, digits, _ . -")
		return
	}
	a.st.mu.RLock()
	adminUser := a.st.st.Admin.User
	a.st.mu.RUnlock()
	if strings.EqualFold(req.Username, adminUser) {
		fail(w, "this username is taken")
		return
	}
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	for _, x := range Ag.f.Agents {
		if x.ID != req.ID && strings.EqualFold(x.Username, req.Username) {
			fail(w, "this username is taken")
			return
		}
	}
	var mgr *Agent
	if me > 0 {
		mgr = Ag.agentLocked(me)
	}
	var x *Agent
	isNew := req.ID == 0
	if isNew {
		if len(req.Password) < 6 {
			fail(w, "password must be at least 6 characters")
			return
		}
		if me > 0 {
			req.Parent = me // an agent creates its sub-agents right below itself
		}
		if req.Parent != 0 && Ag.agentLocked(req.Parent) == nil {
			fail(w, "parent agency not found")
			return
		}
		if me == 0 && req.Parent != 0 && !Ag.agentLocked(req.Parent).Perms.SubAgents {
			fail(w, "the parent agency may not have sub-agents (give it that permission first)")
			return
		}
		if Ag.levelLocked(req.Parent)+1 > Ag.f.Settings.MaxLevels {
			fail(w, fmt.Sprintf("at most %d levels of agencies", Ag.f.Settings.MaxLevels))
			return
		}
		if p := Ag.agentLocked(req.Parent); p != nil && p.Limits.MaxSubAgents > 0 && len(Ag.childrenLocked(p.ID)) >= p.Limits.MaxSubAgents {
			fail(w, fmt.Sprintf("at most %d sub-agents", p.Limits.MaxSubAgents))
			return
		}
		x = &Agent{ID: Ag.f.NextAgent, Parent: req.Parent, Created: nowMs(), CreatedBy: me}
	} else {
		if !Ag.managesLocked(me, req.ID) {
			fail(w, "agent not found")
			return
		}
		x = Ag.agentLocked(req.ID)
	}
	before := agentPublic(x)
	nx := *x // edit a copy; commit only when every check passed
	nx.Username, nx.Brand, nx.Title, nx.Phone, nx.TgChat, nx.Note = req.Username, strings.TrimSpace(req.Brand), strings.TrimSpace(req.Title),
		strings.TrimSpace(req.Phone), strings.TrimSpace(req.TgChat), req.Note
	nx.Enable, nx.Expiry = req.Enable, req.Expiry
	nx.Perms, nx.Limits, nx.Pricing = req.Perms, req.Limits, req.Pricing
	if nx.Pricing.Plans == nil {
		nx.Pricing.Plans = map[string]PlanPrice{}
	}
	if nx.Limits.CreditLimit < 0 || nx.Limits.MaxDebt < 0 || nx.Pricing.Discount < 0 || nx.Pricing.Discount > 100 ||
		nx.Pricing.PerGB < 0 || nx.Pricing.PerDay < 0 || nx.Pricing.AddGB < 0 || nx.Pricing.AddDay < 0 {
		fail(w, "invalid value")
		return
	}
	nx.APIRate = req.APIRate
	if nx.APIRate < 0 || nx.APIRate > 6000 {
		nx.APIRate = 0
	}
	var allow []string
	for _, ip := range req.APIAllow {
		if ip = strings.TrimSpace(ip); ip != "" {
			allow = append(allow, ip)
		}
	}
	nx.APIAllow = allow
	if mgr != nil { // an agent cannot give more than it has
		mp, np := mgr.Perms, &nx.Perms
		np.Create, np.Renew, np.Reset, np.Delete = np.Create && mp.Create, np.Renew && mp.Renew, np.Reset && mp.Reset, np.Delete && mp.Delete
		np.Suspend, np.Edit, np.Unlimited, np.Bulk = np.Suspend && mp.Suspend, np.Edit && mp.Edit, np.Unlimited && mp.Unlimited, np.Bulk && mp.Bulk
		np.SubAgents, np.Transfer, np.API = np.SubAgents && mp.SubAgents, np.Transfer && mp.Transfer, np.API && mp.API
	}
	if req.Password != "" {
		if len(req.Password) < 6 {
			fail(w, "password must be at least 6 characters")
			return
		}
		nx.Hash = hashPass(randHex(8), req.Password)
		nx.TokenVer++
	}
	if !nx.Enable && x.Enable {
		nx.TokenVer++
	}
	// commit, then make sure a reseller does not price a sub-agent below its own price
	key := itoa(nx.ID)
	prev := Ag.f.Agents[key]
	Ag.f.Agents[key] = &nx
	if mgr != nil {
		if msg := Ag.underpricedLocked(nx.ID, me); msg != "" {
			if prev == nil {
				delete(Ag.f.Agents, key)
			} else {
				Ag.f.Agents[key] = prev
			}
			fail(w, msg)
			return
		}
	}
	if isNew {
		Ag.f.NextAgent++
	}
	Ag.refreshFrozenLocked()
	if err := Ag.saveLocked(); err != nil {
		if prev == nil {
			delete(Ag.f.Agents, key)
		} else {
			Ag.f.Agents[key] = prev
		}
		fail(w, err.Error())
		return
	}
	act := "agent:update"
	if isNew {
		act = "agent:create"
	}
	detail := ""
	if bp, _ := json.Marshal(before.Pricing); !isNew {
		if np, _ := json.Marshal(nx.Pricing); string(bp) != string(np) {
			detail = "pricing " + string(bp) + " → " + string(np)
		}
	}
	Ag.logLocked(actorOf(r), act, "agent:"+key, clientIP(r), "%s", strings.TrimSpace(nx.Username+" "+detail))
	ok(w, "saved", agentPublic(&nx))
}

// underpricedLocked: would agent id pay less than its manager me for anything? ("" = no)
func (ag *AgencyStore) underpricedLocked(id, me int) string {
	qs := []Quote{{Kind: "sale", GB: 1}, {Kind: "sale", DaysMs: dayMs}, {Kind: "addgb", GB: 1}, {Kind: "adddays", DaysMs: dayMs}}
	for _, p := range ag.f.Plans {
		if p.Enable {
			qs = append(qs, Quote{Kind: "sale", Plan: p.ID}, Quote{Kind: "renew", Plan: p.ID})
		}
	}
	for _, q := range qs {
		mine, err1 := ag.priceLocked(me, q)
		theirs, err2 := ag.priceLocked(id, q)
		if err1 == nil && err2 == nil && theirs < mine {
			what := map[string]string{"sale": "sale", "addgb": "adding quota", "adddays": "adding time", "renew": "renewal"}[q.Kind]
			if q.Plan > 0 {
				what += " of plan " + ag.f.Plans[itoa(q.Plan)].Name
			}
			return fmt.Sprintf("a sub-agent's price cannot be below your own (%s: %d < %d)", what, theirs, mine)
		}
	}
	return ""
}

func (a *API) agWallet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Op     string `json:"op"` // topup | deduct
		Amount int64  `json:"amount"`
		Note   string `json:"note"`
	}
	if readJSON(r, &req) != nil || req.Amount <= 0 || (req.Op != "topup" && req.Op != "deduct") {
		fail(w, "amount must be positive; op is topup or deduct")
		return
	}
	me, id := agentOf(r), pathID(r)
	Ag.mu.RLock()
	okk := Ag.managesLocked(me, id)
	Ag.mu.RUnlock()
	if !okk {
		fail(w, "agent not found")
		return
	}
	amt := req.Amount
	if req.Op == "deduct" {
		amt = -amt
	}
	e, err := Ag.Credit(id, amt, req.Op, actorOf(r), clientIP(r), strings.TrimSpace(req.Note))
	if err != nil {
		fail(w, err.Error())
		return
	}
	if x, ok2 := Ag.Agent(id); ok2 && x.TgChat != "" {
		Ag.mu.RLock()
		cur := Ag.f.Settings.Currency
		Ag.mu.RUnlock()
		a.st.TgSend(x.TgChat, fmt.Sprintf("💰 کیف پول %s: %+d %s، موجودی %d", x.Username, amt, cur, e.Bal))
	}
	ok(w, "saved", e)
}

func (a *API) agTransfer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From, To int
		Amount   int64
		Note     string
	}
	if readJSON(r, &req) != nil || req.Amount <= 0 || req.From == req.To {
		fail(w, "bad request")
		return
	}
	if err := Ag.Transfer(req.From, req.To, req.Amount, actorOf(r), clientIP(r), req.Note); err != nil {
		fail(w, err.Error())
		return
	}
	ok(w, "transferred", nil)
}

func (a *API) agBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Until  int64  `json:"until"` // -1 = until lifted, 0 = lift the ban, else unix ms
		Reason string `json:"reason"`
	}
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	me, id := agentOf(r), pathID(r)
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	if !Ag.managesLocked(me, id) {
		fail(w, "agent not found")
		return
	}
	x := Ag.agentLocked(id)
	x.BanUntil, x.BanReason = req.Until, strings.TrimSpace(req.Reason)
	if req.Until != 0 {
		x.TokenVer++
	}
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	act := "agent:ban"
	if req.Until == 0 {
		act = "agent:unban"
	}
	Ag.logLocked(actorOf(r), act, "agent:"+itoa(id), clientIP(r), "%d %s", req.Until, x.BanReason)
	ok(w, "saved", nil)
}

// agFreeze stops (or brings back) every account of an agency and of its sub-agents at once,
// without touching the accounts themselves: the agency cannot switch them back on.
func (a *API) agFreeze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		On   bool   `json:"on"`
		Note string `json:"note"`
	}
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	me, id := agentOf(r), pathID(r)
	Ag.mu.Lock()
	if !Ag.managesLocked(me, id) {
		Ag.mu.Unlock()
		fail(w, "agent not found")
		return
	}
	x := Ag.agentLocked(id)
	x.Frozen, x.FrozenNote = req.On, strings.TrimSpace(req.Note)
	err := Ag.saveLocked()
	Ag.refreshFrozenLocked()
	sub := Ag.subtreeLocked(id)
	act := "agent:freeze"
	if !req.On {
		act = "agent:unfreeze"
	}
	Ag.logLocked(actorOf(r), act, "agent:"+itoa(id), clientIP(r), "%s %s", x.Username, x.FrozenNote)
	name, chat := x.Username, x.TgChat
	Ag.mu.Unlock()
	if err != nil {
		fail(w, err.Error())
		return
	}
	n := 0
	var kick []string
	a.st.mu.RLock()
	for _, acc := range a.st.st.Accounts {
		if sub[acc.Owner] {
			n++
			if req.On {
				kick = append(kick, acc.Email)
			}
		}
	}
	a.st.mu.RUnlock()
	for _, e := range kick {
		Sessions.KickEmailWhy(e, "agency accounts suspended by the management")
	}
	if chat != "" {
		if req.On {
			a.st.TgSend(chat, "⛔ همه‌ی اکانت‌های نمایندگی "+name+" توسط مدیریت متوقف شد. "+req.Note)
		} else {
			a.st.TgSend(chat, "✅ اکانت‌های نمایندگی "+name+" دوباره فعال شد.")
		}
	}
	ok(w, "saved", n)
}

func (a *API) agAgentDelete(w http.ResponseWriter, r *http.Request) {
	me, id := agentOf(r), pathID(r)
	a.st.mu.RLock()
	owned := 0
	for _, acc := range a.st.st.Accounts {
		if acc.Owner == id {
			owned++
		}
	}
	a.st.mu.RUnlock()
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	if !Ag.managesLocked(me, id) {
		fail(w, "agent not found")
		return
	}
	switch {
	case owned > 0:
		fail(w, fmt.Sprintf("the agency still owns %d accounts: move or delete them first", owned))
		return
	case len(Ag.childrenLocked(id)) > 0:
		fail(w, "the agency has sub-agents: move or delete them first")
		return
	case Ag.bal[id] != 0:
		fail(w, fmt.Sprintf("the wallet is not empty (%d): bring it to zero first", Ag.bal[id]))
		return
	}
	name := Ag.agentLocked(id).Username
	delete(Ag.f.Agents, itoa(id))
	for _, c := range Ag.f.Customers {
		if c.Owner == id {
			delete(Ag.f.Customers, itoa(c.ID))
		}
	}
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	Ag.logLocked(actorOf(r), "agent:delete", "agent:"+itoa(id), clientIP(r), "%s", name)
	ok(w, "deleted", nil)
}

func (a *API) agAgentMove(w http.ResponseWriter, r *http.Request) {
	var req struct{ Parent int }
	readJSON(r, &req)
	id := pathID(r)
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	x := Ag.agentLocked(id)
	if x == nil || (req.Parent != 0 && Ag.agentLocked(req.Parent) == nil) {
		fail(w, "agent not found")
		return
	}
	if req.Parent != 0 && Ag.isUnderLocked(req.Parent, id) {
		fail(w, "an agency cannot be moved below itself")
		return
	}
	depth := 0 // levels of the moved subtree below x
	for sid := range Ag.subtreeLocked(id) {
		if d := Ag.levelLocked(sid) - Ag.levelLocked(id); d > depth {
			depth = d
		}
	}
	if Ag.levelLocked(req.Parent)+1+depth > Ag.f.Settings.MaxLevels {
		fail(w, fmt.Sprintf("at most %d levels of agencies", Ag.f.Settings.MaxLevels))
		return
	}
	old := x.Parent
	x.Parent = req.Parent
	if err := Ag.saveLocked(); err != nil {
		x.Parent = old
		fail(w, err.Error())
		return
	}
	Ag.refreshFrozenLocked()
	Ag.logLocked(actorOf(r), "agent:move", "agent:"+itoa(id), clientIP(r), "parent %d → %d", old, req.Parent)
	ok(w, "moved", nil)
}

// agImpersonate lets the admin look at the panel as an agency; the admin's own session is kept
// aside and comes back with /back. Everything done meanwhile is logged as admin@agent:N.
func (a *API) agImpersonate(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	x, okk := Ag.Agent(id)
	if !okk {
		fail(w, "agent not found")
		return
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		fail(w, "login required")
		return
	}
	a.st.mu.RLock()
	base := a.st.st.Global.BasePath
	a.st.mu.RUnlock()
	http.SetCookie(w, &http.Cookie{Name: admCookie, Value: c.Value, Path: base, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(12 * time.Hour)})
	a.st.issueAgent(w, id, x.TokenVer, r.TLS != nil)
	Ag.Log("admin", "impersonate", "agent:"+itoa(id), clientIP(r), "%s", x.Username)
	ok(w, "ok", nil)
}

func (a *API) agBack(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(admCookie)
	if err != nil || !a.st.verify(c.Value) {
		fail(w, "no admin session to go back to")
		return
	}
	a.st.mu.RLock()
	base := a.st.st.Global.BasePath
	a.st.mu.RUnlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: c.Value, Path: base, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(12 * time.Hour)})
	http.SetCookie(w, &http.Cookie{Name: admCookie, Value: "", Path: base, MaxAge: -1})
	ok(w, "ok", nil)
}

// ---------------------------------------------------------------- ledger, activity, reports

func parseRange(r *http.Request) (from, to int64) {
	from, _ = strconv.ParseInt(r.Form.Get("from"), 10, 64)
	to, _ = strconv.ParseInt(r.Form.Get("to"), 10, 64)
	if to <= 0 {
		to = math.MaxInt64
	}
	return
}

// scopeAgent picks whose data to show: the caller's own, or (for a manager) one agent below it.
func scopeAgent(r *http.Request) (int, bool) {
	me := agentOf(r)
	id, _ := strconv.Atoi(r.Form.Get("agent"))
	if id == 0 || id == me {
		return me, true
	}
	Ag.mu.RLock()
	defer Ag.mu.RUnlock()
	return id, Ag.managesLocked(me, id)
}

func (a *API) agLedger(w http.ResponseWriter, r *http.Request) {
	who, okk := scopeAgent(r)
	if !okk {
		fail(w, "agent not found")
		return
	}
	from, to := parseRange(r)
	kind := r.Form.Get("kind")
	q := strings.ToLower(strings.TrimSpace(r.Form.Get("q")))
	limit, _ := strconv.Atoi(r.Form.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	csv := r.Form.Get("format") == "csv"
	Ag.mu.RLock()
	names := map[int]string{}
	for _, x := range Ag.f.Agents {
		names[x.ID] = x.Username
	}
	var out []LedgerEntry
	for i := len(Ag.ledger) - 1; i >= 0; i-- {
		e := Ag.ledger[i]
		if who > 0 && e.Agent != who {
			continue
		}
		if e.T < from || e.T > to || (kind != "" && e.Kind != kind) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Acct+" "+e.Note+" "+names[e.Agent]), q) {
			continue
		}
		out = append(out, e)
		if !csv && len(out) >= limit {
			break
		}
	}
	bal := Ag.bal[who]
	cur := Ag.f.Settings.Currency
	Ag.mu.RUnlock()
	if csv {
		var b strings.Builder
		b.WriteString("\ufeffid,time,agency,kind,amount,balance,account,gb,days,plan,profit,by,ip,note\n")
		for _, e := range out {
			fmt.Fprintf(&b, "%d,%s,%s,%s,%d,%d,%s,%.2f,%.2f,%d,%d,%s,%s,%s\n", e.ID, time.UnixMilli(e.T).Format("2006-01-02 15:04:05"),
				csvCell(names[e.Agent]), e.Kind, e.Amt, e.Bal, csvCell(e.Acct), e.GB, e.Days, e.Plan, e.Profit, csvCell(e.By), e.IP, csvCell(e.Note))
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ledger-%s.csv"`, time.Now().Format("20060102-1504")))
		io.WriteString(w, b.String())
		return
	}
	if out == nil {
		out = []LedgerEntry{}
	}
	ok(w, "", map[string]any{"items": out, "balance": bal, "currency": cur, "names": names})
}

func csvCell(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (a *API) agActivity(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	action := r.Form.Get("action")
	q := strings.ToLower(strings.TrimSpace(r.Form.Get("q")))
	Ag.mu.RLock()
	actors := map[string]bool{}
	if me > 0 {
		for id := range Ag.subtreeLocked(me) {
			actors["agent:"+itoa(id)], actors["api:"+itoa(id)], actors["admin@agent:"+itoa(id)] = true, true, true
		}
	}
	var out []Activity
	for i := len(Ag.acts) - 1; i >= 0 && len(out) < 1000; i-- {
		x := Ag.acts[i]
		if me > 0 && !actors[x.Actor] {
			continue
		}
		if action != "" && !strings.HasPrefix(x.Action, action) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(x.Actor+" "+x.Target+" "+x.Detail+" "+x.IP), q) {
			continue
		}
		out = append(out, x)
	}
	Ag.mu.RUnlock()
	if out == nil {
		out = []Activity{}
	}
	ok(w, "", out)
}

func (a *API) agAPILog(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	sub := agSubtree(me)
	apiLog.Lock()
	var out []apiLogEntry
	for i := len(apiLog.b) - 1; i >= 0 && len(out) < 500; i-- {
		e := apiLog.b[i]
		if me == 0 || sub[e.Agent] {
			out = append(out, e)
		}
	}
	apiLog.Unlock()
	if out == nil {
		out = []apiLogEntry{}
	}
	ok(w, "", out)
}

func bucketOf(t int64, group string) string {
	tm := time.UnixMilli(t)
	switch group {
	case "month":
		return tm.Format("2006-01")
	case "week":
		wd := (int(tm.Weekday()) + 1) % 7 // weeks start on Saturday
		return tm.AddDate(0, 0, -wd).Format("2006-01-02")
	}
	return tm.Format("2006-01-02")
}

type repRow struct {
	K       string  `json:"k"`
	Sales   int     `json:"sales"`   // new accounts
	Renews  int     `json:"renews"`  // renewals, added quota or time, resets
	GB      float64 `json:"gb"`      // quota sold
	Revenue int64   `json:"revenue"` // what the viewer received (admin) / paid (agent), net of refunds
	Profit  int64   `json:"profit"`  // what the viewer earned on its sub-agents' sales
	Refunds int64   `json:"refunds"`
	Topups  int64   `json:"topups"`
}

type repAgent struct {
	ID       int     `json:"id"`
	Username string  `json:"username"`
	Brand    string  `json:"brand"`
	Parent   int     `json:"parent"`
	Sales    int     `json:"sales"`
	Renews   int     `json:"renews"`
	GB       float64 `json:"gb"`
	Paid     int64   `json:"paid"`   // what it paid for its own and its subtree's sales
	Profit   int64   `json:"profit"` // what it earned on its sub-agents
	Balance  int64   `json:"balance"`
	LastSale int64   `json:"lastSale"`
}

func (a *API) agReports(w http.ResponseWriter, r *http.Request) {
	root, okk := scopeAgent(r)
	if !okk {
		fail(w, "agent not found")
		return
	}
	from, to := parseRange(r)
	group := r.Form.Get("group")
	inactiveDays, _ := strconv.Atoi(r.Form.Get("inactive"))
	if inactiveDays <= 0 {
		inactiveDays = 7
	}
	Ag.mu.RLock()
	sub := Ag.subtreeLocked(root) // root 0 = everything
	inScope := func(id int) bool { return root == 0 || sub[id] }
	// net paid per sale per agent, and the seller of each sale
	type saleInfo struct {
		seller   int
		kind     string
		t        int64
		gb       float64
		svc      string
		plan     int
		reversed bool // the core refused it: it never happened
		net      map[int]int64
	}
	sales := map[int64]*saleInfo{}
	var topups = map[string]int64{}
	totals := repRow{K: "total"}
	series := map[string]*repRow{}
	row := func(k string) *repRow {
		x := series[k]
		if x == nil {
			x = &repRow{K: k}
			series[k] = x
		}
		return x
	}
	for _, e := range Ag.ledger {
		if e.T < from || e.T > to {
			continue
		}
		if e.Sale == 0 {
			if (e.Kind == "topup" || e.Kind == "deduct") && inScope(e.Agent) && (root == 0 || e.Agent != root) {
				k := bucketOf(e.T, group)
				topups[k] += e.Amt
			}
			continue
		}
		s := sales[e.Sale]
		if s == nil {
			s = &saleInfo{seller: e.Seller, net: map[int]int64{}}
			sales[e.Sale] = s
		}
		if chargeKinds[e.Kind] && s.kind == "" {
			s.kind, s.t, s.gb, s.svc, s.plan = e.Kind, e.T, e.GB, e.Svc, e.Plan
		}
		if e.Kind == "reversal" {
			s.reversed = true
		}
		s.net[e.Agent] -= e.Amt
	}
	agents := map[int]*repAgent{}
	for _, x := range Ag.f.Agents {
		if x.ID != root && inScope(x.ID) {
			agents[x.ID] = &repAgent{ID: x.ID, Username: x.Username, Brand: x.Brand, Parent: x.Parent, Balance: Ag.bal[x.ID]}
		}
	}
	protos := map[string]*struct {
		Count  int   `json:"count"`
		Amount int64 `json:"amount"`
	}{}
	plans := map[int]*struct {
		Name   string `json:"name"`
		Count  int    `json:"count"`
		Amount int64  `json:"amount"`
	}{}
	for _, s := range sales {
		if s.kind == "" || s.reversed || !inScope(s.seller) {
			continue // a sale entirely reversed in the range, or outside the viewer's tree
		}
		chain := Ag.chainLocked(s.seller)
		// what the viewer got (admin: the top-level agency's net payment) or paid (agent: its own net)
		var revenue, profit int64
		if root == 0 {
			if len(chain) > 0 {
				revenue = s.net[chain[len(chain)-1].ID]
				profit = revenue
			}
		} else {
			revenue = s.net[root]
			for i, x := range chain {
				if x.ID == root && i > 0 {
					profit = s.net[chain[i-1].ID] - s.net[root]
				}
			}
		}
		k := bucketOf(s.t, group)
		rr := row(k)
		for _, x := range []*repRow{rr, &totals} {
			if s.kind == "sale" {
				x.Sales++
			} else {
				x.Renews++
			}
			x.GB += s.gb
			x.Revenue += revenue
			x.Profit += profit
		}
		for i, x := range chain {
			ra := agents[x.ID]
			if ra == nil {
				continue
			}
			ra.Paid += s.net[x.ID]
			if i == 0 {
				if s.kind == "sale" {
					ra.Sales++
				} else {
					ra.Renews++
				}
				ra.GB += s.gb
				if s.t > ra.LastSale {
					ra.LastSale = s.t
				}
			} else {
				ra.Profit += s.net[chain[i-1].ID] - s.net[x.ID]
			}
		}
		for _, p := range strings.Split(s.svc, ",") {
			if p == "" {
				continue
			}
			x := protos[p]
			if x == nil {
				x = &struct {
					Count  int   `json:"count"`
					Amount int64 `json:"amount"`
				}{}
				protos[p] = x
			}
			x.Count++
			x.Amount += revenue
		}
		if s.plan > 0 {
			x := plans[s.plan]
			if x == nil {
				name := "#" + itoa(s.plan)
				if p := Ag.f.Plans[itoa(s.plan)]; p != nil {
					name = p.Name
				}
				x = &struct {
					Name   string `json:"name"`
					Count  int    `json:"count"`
					Amount int64  `json:"amount"`
				}{Name: name}
				plans[s.plan] = x
			}
			x.Count++
			x.Amount += revenue
		}
	}
	// refunds (entries of kind refund) are already netted in s.net; count them separately too
	for _, e := range Ag.ledger {
		if e.Kind == "refund" && e.T >= from && e.T <= to && (root == 0 && Ag.levelLocked(e.Agent) == 1 || e.Agent == root) {
			totals.Refunds += e.Amt
			row(bucketOf(e.T, group)).Refunds += e.Amt
		}
	}
	// last sale ever (not only in the range) for the inactivity list
	lastEver := map[int]int64{}
	for _, e := range Ag.ledger {
		if chargeKinds[e.Kind] && e.Agent == e.Seller && e.T > lastEver[e.Agent] {
			lastEver[e.Agent] = e.T
		}
	}
	cur := Ag.f.Settings.Currency
	Ag.mu.RUnlock()

	for k, v := range topups {
		row(k).Topups += v
		totals.Topups += v
	}
	var srs []repRow
	for _, v := range series {
		srs = append(srs, *v)
	}
	sort.Slice(srs, func(i, j int) bool { return srs[i].K < srs[j].K })
	var ags []repAgent
	var inactive, debtors []map[string]any
	now := nowMs()
	for _, v := range agents {
		ags = append(ags, *v)
		if le := lastEver[v.ID]; now-le > int64(inactiveDays)*dayMs {
			inactive = append(inactive, map[string]any{"id": v.ID, "username": v.Username, "lastSale": le})
		}
		if v.Balance < 0 {
			debtors = append(debtors, map[string]any{"id": v.ID, "username": v.Username, "balance": v.Balance})
		}
	}
	sort.Slice(ags, func(i, j int) bool { return ags[i].Paid > ags[j].Paid })
	if r.Form.Get("format") == "csv" {
		var b strings.Builder
		b.WriteString("\ufeffperiod,new accounts,renewals,GB,revenue,profit,refunds,top-ups\n")
		for _, x := range append(srs, totals) {
			fmt.Fprintf(&b, "%s,%d,%d,%.2f,%d,%d,%d,%d\n", x.K, x.Sales, x.Renews, x.GB, x.Revenue, x.Profit, x.Refunds, x.Topups)
		}
		b.WriteString("\nagency,brand,new accounts,renewals,GB,paid,profit,balance,last sale\n")
		for _, x := range ags {
			ls := ""
			if x.LastSale > 0 {
				ls = time.UnixMilli(x.LastSale).Format("2006-01-02 15:04")
			}
			fmt.Fprintf(&b, "%s,%s,%d,%d,%.2f,%d,%d,%d,%s\n", csvCell(x.Username), csvCell(x.Brand), x.Sales, x.Renews, x.GB, x.Paid, x.Profit, x.Balance, ls)
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.csv"`, time.Now().Format("20060102-1504")))
		io.WriteString(w, b.String())
		return
	}
	if srs == nil {
		srs = []repRow{}
	}
	if ags == nil {
		ags = []repAgent{}
	}
	ok(w, "", map[string]any{"totals": totals, "series": srs, "agents": ags, "protocols": protos, "plans": plans,
		"inactive": inactive, "debtors": debtors, "currency": cur, "root": root})
}

// ---------------------------------------------------------------- dashboard

func (a *API) agDashboard(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	now := nowMs()
	on := onlineCounts()
	out := map[string]any{}
	if me > 0 {
		sub := agSubtree(me)
		type acct struct {
			Email  string `json:"email"`
			Expiry int64  `json:"expiry"`
			Used   int64  `json:"used"`
			Total  int64  `json:"total"`
		}
		st := map[string]int{}
		var expiring, low []acct
		own, subAcc, online := 0, 0, 0
		var usedSum int64
		a.st.mu.RLock()
		for _, acc := range a.st.st.Accounts {
			if !mine(sub, acc) {
				continue
			}
			if acc.Owner != me {
				subAcc++
				continue
			}
			own++
			usedSum += acc.Up + acc.Down
			s := statusOf(acc, now)
			st[s]++
			online += on[strings.ToLower(acc.Email)]
			if s == "active" && acc.ExpiryTime > 0 && acc.ExpiryTime-now < 3*dayMs {
				expiring = append(expiring, acct{acc.Email, acc.ExpiryTime, acc.Up + acc.Down, acc.TotalGB})
			}
			if s == "active" && acc.TotalGB > 0 && float64(acc.Up+acc.Down) >= 0.9*float64(acc.TotalGB) {
				low = append(low, acct{acc.Email, acc.ExpiryTime, acc.Up + acc.Down, acc.TotalGB})
			}
		}
		a.st.mu.RUnlock()
		sort.Slice(expiring, func(i, j int) bool { return expiring[i].Expiry < expiring[j].Expiry })
		if len(expiring) > 30 {
			expiring = expiring[:30]
		}
		if len(low) > 30 {
			low = low[:30]
		}
		out["accounts"] = map[string]any{"own": own, "subtree": subAcc, "status": st, "online": online, "used": usedSum}
		out["frozen"] = ownerFrozen(me)
		out["expiring"], out["low"] = expiring, low
		Ag.mu.RLock()
		x := Ag.agentLocked(me)
		out["balance"] = Ag.bal[me]
		out["creditLimit"] = max(x.Limits.CreditLimit, x.Limits.MaxDebt)
		out["children"] = len(Ag.childrenLocked(me))
		periods := map[string]int64{"today": dayStart(now), "week": now - 7*dayMs, "month": now - 30*dayMs}
		stats := map[string]map[string]int64{}
		for k := range periods {
			stats[k] = map[string]int64{}
		}
		var recent []LedgerEntry
		for i := len(Ag.ledger) - 1; i >= 0; i-- {
			e := Ag.ledger[i]
			if e.Agent != me {
				continue
			}
			if len(recent) < 10 {
				recent = append(recent, e)
			}
			if e.T < periods["month"] && len(recent) >= 10 {
				break
			}
			for k, since := range periods {
				if e.T < since || e.Sale == 0 {
					continue
				}
				m := stats[k]
				if e.Seller == me {
					if chargeKinds[e.Kind] {
						if e.Kind == "sale" {
							m["sales"]++
						} else {
							m["renews"]++
						}
					}
					m["paid"] -= e.Amt
				} else {
					m["profit"] += e.Profit
					m["subPaid"] -= e.Amt
				}
			}
		}
		Ag.mu.RUnlock()
		out["stats"], out["recent"] = stats, recent
		ok(w, "", out)
		return
	}
	// the admin's agency overview
	Ag.mu.RLock()
	var balSum, debt int64
	lowBal := []map[string]any{}
	for _, x := range Ag.f.Agents {
		b := Ag.bal[x.ID]
		balSum += b
		if b < 0 {
			debt += b
		}
		if Ag.f.Settings.LowBalance > 0 && b < Ag.f.Settings.LowBalance && x.Enable {
			lowBal = append(lowBal, map[string]any{"id": x.ID, "username": x.Username, "balance": b})
		}
	}
	periods := map[string]int64{"today": dayStart(now), "week": now - 7*dayMs, "month": now - 30*dayMs}
	stats := map[string]map[string]int64{}
	for k := range periods {
		stats[k] = map[string]int64{}
	}
	top := map[int]int64{}
	for i := len(Ag.ledger) - 1; i >= 0; i-- {
		e := Ag.ledger[i]
		if e.T < periods["month"] {
			break
		}
		if e.Sale == 0 {
			if e.Kind == "topup" {
				for k, since := range periods {
					if e.T >= since {
						stats[k]["topups"] += e.Amt
					}
				}
			}
			continue
		}
		top1 := Ag.levelLocked(e.Agent) == 1
		for k, since := range periods {
			if e.T < since {
				continue
			}
			if top1 {
				stats[k]["revenue"] -= e.Amt
			}
			if e.Agent == e.Seller && chargeKinds[e.Kind] {
				if e.Kind == "sale" {
					stats[k]["sales"]++
				} else {
					stats[k]["renews"]++
				}
			}
		}
		if top1 {
			top[e.Agent] -= e.Amt
		}
	}
	type topRow struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Amount   int64  `json:"amount"`
	}
	var tops []topRow
	for id, v := range top {
		if x := Ag.agentLocked(id); x != nil {
			tops = append(tops, topRow{id, x.Username, v})
		}
	}
	nAgents := len(Ag.f.Agents)
	pending := 0
	for _, q := range Ag.f.Requests {
		if q.Status == "pending" {
			pending++
		}
	}
	Ag.mu.RUnlock()
	sort.Slice(tops, func(i, j int) bool { return tops[i].Amount > tops[j].Amount })
	if len(tops) > 5 {
		tops = tops[:5]
	}
	agentAccounts := 0
	a.st.mu.RLock()
	for _, acc := range a.st.st.Accounts {
		if acc.Owner > 0 {
			agentAccounts++
		}
	}
	a.st.mu.RUnlock()
	ok(w, "", map[string]any{"agents": nAgents, "balances": balSum, "debt": debt, "lowBalance": lowBal, "stats": stats, "top": tops,
		"agentAccounts": agentAccounts, "pendingRequests": pending})
}

func dayStart(ms int64) int64 {
	y, m, d := time.UnixMilli(ms).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local).UnixMilli()
}

// ---------------------------------------------------------------- customers

func agOwnsCustomer(me, id int) bool {
	Ag.mu.RLock()
	defer Ag.mu.RUnlock()
	c := Ag.f.Customers[itoa(id)]
	return c != nil && (me == 0 || c.Owner == me)
}

func (a *API) agCustomers(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	who, okk := scopeAgent(r)
	if !okk {
		fail(w, "agent not found")
		return
	}
	type row struct {
		Customer
		Accounts int `json:"accounts"`
		Active   int `json:"active"`
	}
	counts := map[int][2]int{}
	now := nowMs()
	a.st.mu.RLock()
	for _, acc := range a.st.st.Accounts {
		if acc.Customer > 0 {
			c := counts[acc.Customer]
			c[0]++
			if statusOf(acc, now) == "active" {
				c[1]++
			}
			counts[acc.Customer] = c
		}
	}
	a.st.mu.RUnlock()
	Ag.mu.RLock()
	var out []row
	all := me == 0 && r.Form.Get("agent") == ""
	for _, c := range Ag.f.Customers {
		if !all && c.Owner != who {
			continue
		}
		n := counts[c.ID]
		out = append(out, row{*c, n[0], n[1]})
	}
	Ag.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if out == nil {
		out = []row{}
	}
	ok(w, "", out)
}

func (a *API) agCustomerSave(w http.ResponseWriter, r *http.Request) {
	var c Customer
	if readJSON(r, &c) != nil || strings.TrimSpace(c.Name) == "" {
		fail(w, "a name is required")
		return
	}
	me := agentOf(r)
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	if c.ID == 0 {
		c.ID = Ag.f.NextCust
		Ag.f.NextCust++
		c.Owner, c.Created = me, nowMs()
	} else {
		old := Ag.f.Customers[itoa(c.ID)]
		if old == nil || (me > 0 && old.Owner != me) {
			fail(w, "customer not found")
			return
		}
		c.Owner, c.Created = old.Owner, old.Created
	}
	c.Name, c.Phone, c.TgID = strings.TrimSpace(c.Name), strings.TrimSpace(c.Phone), strings.TrimSpace(c.TgID)
	Ag.f.Customers[itoa(c.ID)] = &c
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	ok(w, "saved", c)
}

func (a *API) agCustomerDel(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID int }
	readJSON(r, &req)
	me := agentOf(r)
	Ag.mu.Lock()
	c := Ag.f.Customers[itoa(req.ID)]
	if c == nil || (me > 0 && c.Owner != me) {
		Ag.mu.Unlock()
		fail(w, "customer not found")
		return
	}
	delete(Ag.f.Customers, itoa(req.ID))
	err := Ag.saveLocked()
	Ag.mu.Unlock()
	if err != nil {
		fail(w, err.Error())
		return
	}
	a.st.mu.Lock()
	for _, acc := range a.st.st.Accounts {
		if acc.Customer == req.ID {
			acc.Customer = 0
		}
	}
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "deleted", nil)
}

func (a *API) agSetCustomer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Emails   []string `json:"emails"`
		Customer int      `json:"customer"`
	}
	if readJSON(r, &req) != nil || len(req.Emails) == 0 {
		fail(w, "bad request")
		return
	}
	me := agentOf(r)
	if req.Customer > 0 && !agOwnsCustomer(me, req.Customer) {
		fail(w, "customer not found")
		return
	}
	sub := agSubtree(me)
	n := 0
	a.st.mu.Lock()
	for _, e := range req.Emails {
		if acc := a.st.st.Accounts[ekey(e)]; acc != nil && (me == 0 || mine(sub, acc)) {
			acc.Customer = req.Customer
			n++
		}
	}
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "saved", n)
}

// agMoveAccounts hands accounts to another owner. The admin moves anything anywhere; a reseller
// with the transfer permission moves within its own tree, and asks the admin for anything else.
func (a *API) agMoveAccounts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Emails []string `json:"emails"`
		Owner  int      `json:"owner"`
		To     string   `json:"to"` // or the receiving agency's username
		Note   string   `json:"note"`
	}
	if readJSON(r, &req) != nil || len(req.Emails) == 0 {
		fail(w, "bad request")
		return
	}
	me := agentOf(r)
	Ag.mu.RLock()
	if req.To != "" {
		req.Owner = -1
		for _, x := range Ag.f.Agents {
			if strings.EqualFold(x.Username, strings.TrimSpace(req.To)) {
				req.Owner = x.ID
			}
		}
	}
	exists := req.Owner == 0 || Ag.agentLocked(req.Owner) != nil
	inTree := me == 0 || (req.Owner > 0 && Ag.isUnderLocked(req.Owner, me))
	var perms AgentPerms
	if x := Ag.agentLocked(me); x != nil {
		perms = x.Perms
	}
	Ag.mu.RUnlock()
	if !exists || (me > 0 && req.Owner == 0) {
		fail(w, "agency not found")
		return
	}
	sub := agSubtree(me)
	var emails []string
	a.st.mu.RLock()
	for _, e := range req.Emails {
		if acc := a.st.st.Accounts[ekey(e)]; acc != nil && (me == 0 || mine(sub, acc)) {
			emails = append(emails, acc.Email)
		}
	}
	a.st.mu.RUnlock()
	if len(emails) == 0 {
		fail(w, "no such accounts")
		return
	}
	if me > 0 && !perms.Transfer {
		fail(w, "your agency may not move accounts")
		return
	}
	if !inTree { // outside the reseller's tree: the admin decides
		Ag.mu.Lock()
		q := &MoveRequest{ID: Ag.f.NextReq, From: me, To: req.Owner, Emails: emails, Note: strings.TrimSpace(req.Note), T: nowMs(), Status: "pending"}
		Ag.f.NextReq++
		Ag.f.Requests = append(Ag.f.Requests, q)
		if len(Ag.f.Requests) > 1000 {
			Ag.f.Requests = Ag.f.Requests[len(Ag.f.Requests)-1000:]
		}
		err := Ag.saveLocked()
		Ag.logLocked(actorOf(r), "request", "agent:"+itoa(req.Owner), clientIP(r), "move %d accounts", len(emails))
		Ag.mu.Unlock()
		if err != nil {
			fail(w, err.Error())
			return
		}
		a.st.TgNotify(fmt.Sprintf("📨 درخواست انتقال %d اکانت از نمایندگی #%d به #%d", len(emails), me, req.Owner))
		ok(w, "sent to the admin for approval", map[string]any{"request": q.ID})
		return
	}
	n := a.moveOwner(emails, req.Owner, func(acc *Account) bool { return me == 0 || mine(sub, acc) })
	Ag.Log(actorOf(r), "accounts:move", "agent:"+itoa(req.Owner), clientIP(r), "%d accounts: %s", n, strings.Join(emails, " "))
	ok(w, "moved", n)
}

func (a *API) moveOwner(emails []string, owner int, allow func(*Account) bool) int {
	n := 0
	a.st.mu.Lock()
	for _, e := range emails {
		if acc := a.st.st.Accounts[ekey(e)]; acc != nil && allow(acc) {
			acc.Owner = owner
			acc.Customer = 0 // customer records belong to the old owner
			n++
		}
	}
	if n > 0 {
		a.st.touch()
	}
	a.st.mu.Unlock()
	return n
}

func (a *API) agRequests(w http.ResponseWriter, r *http.Request) {
	me := agentOf(r)
	Ag.mu.RLock()
	var out []MoveRequest
	for i := len(Ag.f.Requests) - 1; i >= 0; i-- {
		q := Ag.f.Requests[i]
		if me == 0 || q.From == me || q.To == me {
			out = append(out, *q)
		}
	}
	names := map[int]string{0: "admin"}
	for _, x := range Ag.f.Agents {
		names[x.ID] = x.Username
	}
	Ag.mu.RUnlock()
	if out == nil {
		out = []MoveRequest{}
	}
	ok(w, "", map[string]any{"items": out, "names": names})
}

func (a *API) agRequestDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      int    `json:"id"`
		Approve bool   `json:"approve"`
		Reply   string `json:"reply"`
	}
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	Ag.mu.Lock()
	var q *MoveRequest
	for _, x := range Ag.f.Requests {
		if x.ID == req.ID {
			q = x
		}
	}
	if q == nil || q.Status != "pending" {
		Ag.mu.Unlock()
		fail(w, "request not found")
		return
	}
	from, to := q.From, q.To
	sub := Ag.subtreeLocked(from)
	emails := append([]string(nil), q.Emails...)
	q.Status, q.Decided, q.Reply = "rejected", nowMs(), strings.TrimSpace(req.Reply)
	if req.Approve {
		q.Status = "approved"
	}
	err := Ag.saveLocked()
	Ag.logLocked(actorOf(r), "request:"+q.Status, "agent:"+itoa(to), clientIP(r), "#%d from %d", q.ID, from)
	Ag.mu.Unlock()
	if err != nil {
		fail(w, err.Error())
		return
	}
	n := 0
	if req.Approve {
		n = a.moveOwner(emails, to, func(acc *Account) bool { return mine(sub, acc) })
	}
	ok(w, "saved", n)
}

// ---------------------------------------------------------------- API keys

// keyOwner picks whose keys: the caller's own (it needs the API permission), or, for the admin, any agency's.
func keyOwner(r *http.Request) (int, string) {
	me := agentOf(r)
	if me == 0 {
		id, _ := strconv.Atoi(r.Form.Get("agent"))
		if _, okk := Ag.Agent(id); !okk {
			return 0, "agent not found"
		}
		return id, ""
	}
	if agCtxOf(r).via == "api" {
		return 0, "API keys are managed from the panel"
	}
	if x, _ := Ag.Agent(me); !x.Perms.API {
		return 0, "API access is not enabled for your agency"
	}
	return me, ""
}

func (a *API) agKeys(w http.ResponseWriter, r *http.Request) {
	id, why := keyOwner(r)
	if why != "" {
		fail(w, why)
		return
	}
	x, _ := Ag.Agent(id)
	p := agentPublic(&x)
	ok(w, "", map[string]any{"keys": p.APIKeys, "allow": p.APIAllow, "rate": p.APIRate})
}

func (a *API) agKeyNew(w http.ResponseWriter, r *http.Request) {
	id, why := keyOwner(r)
	if why != "" {
		fail(w, why)
		return
	}
	var req struct{ Name string }
	readJSON(r, &req)
	kid, key := newAPIKey()
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	x := Ag.agentLocked(id)
	if len(x.APIKeys) >= 5 {
		fail(w, "at most 5 keys: delete one first")
		return
	}
	x.APIKeys = append(x.APIKeys, APIKey{ID: kid, Hash: hashPass(randHex(8), key), Name: strings.TrimSpace(req.Name), Created: nowMs()})
	if err := Ag.saveLocked(); err != nil {
		x.APIKeys = x.APIKeys[:len(x.APIKeys)-1]
		fail(w, err.Error())
		return
	}
	Ag.logLocked(actorOf(r), "apikey:new", "agent:"+itoa(id), clientIP(r), "%s %s", kid, req.Name)
	ok(w, "the key is shown only once: copy it now", map[string]any{"id": kid, "key": key})
}

func (a *API) agKeyDel(w http.ResponseWriter, r *http.Request) {
	id, why := keyOwner(r)
	if why != "" {
		fail(w, why)
		return
	}
	var req struct{ ID string }
	readJSON(r, &req)
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	x := Ag.agentLocked(id)
	keep := x.APIKeys[:0:0]
	for _, k := range x.APIKeys {
		if k.ID != req.ID {
			keep = append(keep, k)
		}
	}
	if len(keep) == len(x.APIKeys) {
		fail(w, "key not found")
		return
	}
	x.APIKeys = keep
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	Ag.logLocked(actorOf(r), "apikey:delete", "agent:"+itoa(id), clientIP(r), "%s", req.ID)
	ok(w, "deleted", nil)
}

func (a *API) agKeyAllow(w http.ResponseWriter, r *http.Request) {
	id, why := keyOwner(r)
	if why != "" {
		fail(w, why)
		return
	}
	var req struct {
		Allow []string `json:"allow"`
		Rate  int      `json:"rate"`
	}
	if readJSON(r, &req) != nil {
		fail(w, "bad request")
		return
	}
	var allow []string
	for _, ip := range req.Allow {
		if ip = strings.TrimSpace(ip); ip != "" {
			if net.ParseIP(ip) == nil {
				fail(w, "not an IP address: "+ip)
				return
			}
			allow = append(allow, ip)
		}
	}
	if req.Rate < 0 || req.Rate > 600 {
		fail(w, "rate: 0 to 600 requests per minute")
		return
	}
	Ag.mu.Lock()
	defer Ag.mu.Unlock()
	x := Ag.agentLocked(id)
	x.APIAllow, x.APIRate = allow, req.Rate
	if err := Ag.saveLocked(); err != nil {
		fail(w, err.Error())
		return
	}
	Ag.logLocked(actorOf(r), "apikey:allow", "agent:"+itoa(id), clientIP(r), "%v rate %d", allow, req.Rate)
	ok(w, "saved", nil)
}
