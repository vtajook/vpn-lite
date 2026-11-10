package main

// Reseller (agency) module.
//
// Agents form a tree under the admin (Parent 0 = the admin). Each agent has a wallet whose
// balance is the sum of an APPEND-ONLY ledger (agency/ledger.jsonl, fsync'ed per write): nothing
// is ever edited or deleted, a mistake is undone by a new entry. Definitions (agents, plans,
// settings, customers) live in agency/agency.json, written atomically.
//
// It never changes how the VPN core works: accounts only gain an Owner, every charge is taken
// BEFORE the core is touched, and a core failure after a charge is undone by a reversal entry.
//
// Money model ("cascade"): when an agent sells, the agent AND every ancestor pay their own price
// for that sale, each from their own wallet. An agent's price is set by its parent (the admin for
// top-level agents); an unset price is inherited from the parent's own price, so by default a
// parent earns nothing on its sub-agents until it sets them a higher price. The profit of a
// parent on a sub-agent's sale is (child's price - parent's price). Topping up a sub-agent is
// therefore NOT taken from the parent's wallet: the parent collects that money itself, and pays
// the admin through its own wallet whenever its subtree sells.

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const gib = 1 << 30
const dayMs = 86400000

// ---------------------------------------------------------------- model

type AgentPerms struct {
	Create    bool `json:"create"`    // sell new accounts
	Renew     bool `json:"renew"`     // add time / quota to own accounts
	Reset     bool `json:"reset"`     // reset used traffic (charged as the GB it gives back)
	Delete    bool `json:"delete"`    // delete own accounts (refund by the panel's rules)
	Suspend   bool `json:"suspend"`   // enable / disable own accounts
	Edit      bool `json:"edit"`      // change password, devices, comment, services of own accounts
	Unlimited bool `json:"unlimited"` // may sell 0 = unlimited quota or time
	Bulk      bool `json:"bulk"`      // bulk create / bulk extend
	SubAgents bool `json:"subAgents"` // create and manage sub-agents
	Transfer  bool `json:"transfer"`  // move credit from own wallet to own sub-agents
	API       bool `json:"api"`       // personal API keys
}

type AgentLimits struct {
	MaxCustomers    int     `json:"maxCustomers"`    // accounts owned (0 = no limit)
	MaxActive       int     `json:"maxActive"`       // accounts owned that are usable now
	MaxDailyCreates int     `json:"maxDailyCreates"` // new accounts per calendar day
	MaxSoldGB       float64 `json:"maxSoldGB"`       // GB sold in total (sales, added quota, resets)
	MaxDays         int     `json:"maxDays"`         // longest single sale or extension
	MaxGB           float64 `json:"maxGB"`           // biggest single account quota
	MaxDevices      int     `json:"maxDevices"`      // simultaneous connections per account
	Inbounds        []int   `json:"inbounds"`        // services they may sell (empty = what the parent may)
	MaxSubAgents    int     `json:"maxSubAgents"`    // direct sub-agents (0 = no limit when allowed)
	CreditLimit     int64   `json:"creditLimit"`     // how far below zero the wallet may go
	MaxDebt         int64   `json:"maxDebt"`         // alias kept for the UI: same as CreditLimit
}

// PlanPrice is one agent's price for one plan (0 = inherit the parent's price).
type PlanPrice struct {
	Sell  int64 `json:"sell"`
	Renew int64 `json:"renew"`
}

type AgentPricing struct {
	PerGB    int64                `json:"perGB"`    // custom sale, per GB
	PerDay   int64                `json:"perDay"`   // custom sale, per day
	AddGB    int64                `json:"addGB"`    // adding quota (0 = PerGB)
	AddDay   int64                `json:"addDay"`   // adding time (0 = PerDay)
	Plans    map[string]PlanPrice `json:"plans"`    // plan id -> price for this agent
	Discount int                  `json:"discount"` // percent off every price this agent pays
}

type APIKey struct {
	ID      string `json:"id"`
	Hash    string `json:"hash,omitempty"` // the key itself is shown once and never stored
	Name    string `json:"name"`
	Created int64  `json:"created"`
	LastUse int64  `json:"lastUse"`
}

type Agent struct {
	ID        int          `json:"id"`
	Parent    int          `json:"parent"` // 0 = the admin
	Username  string       `json:"username"`
	Hash      string       `json:"hash,omitempty"`
	TokenVer  int          `json:"tokenVer"` // bumped to end every session of this agent
	Brand     string       `json:"brand"`    // trade name
	Title     string       `json:"title"`    // agency title
	Phone     string       `json:"phone"`
	TgChat    string       `json:"tgChat"` // numeric Telegram chat id for notices to the agent
	Note      string       `json:"note"`
	Enable    bool         `json:"enable"`
	BanUntil  int64        `json:"banUntil"` // -1 = banned for good, > now = banned until then
	BanReason string       `json:"banReason"`
	Expiry    int64        `json:"expiry"` // agency ends (0 = never)
	Created   int64        `json:"created"`
	CreatedBy int          `json:"createdBy"` // 0 = admin
	Perms     AgentPerms   `json:"perms"`
	Limits    AgentLimits  `json:"limits"`
	Pricing   AgentPricing `json:"pricing"`
	APIKeys   []APIKey     `json:"apiKeys"`
	APIAllow  []string     `json:"apiAllow"` // IPs allowed to use the API keys (empty = any)
	APIRate   int          `json:"apiRate"`  // API requests per minute (0 = 120)
}

type Plan struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	GB       float64 `json:"gb"`   // 0 = unlimited quota
	Days     float64 `json:"days"` // 0 = unlimited time; fractions allowed (0.0834 = 2 h)
	Price    int64   `json:"price"`
	Renew    int64   `json:"renew"`    // renewal price (0 = Price)
	Devices  int     `json:"devices"`  // simultaneous connections (0 = panel default)
	Inbounds []int   `json:"inbounds"` // services the plan includes (empty = all the seller may sell)
	Enable   bool    `json:"enable"`
	Order    int     `json:"order"`
}

type Customer struct {
	ID      int    `json:"id"`
	Owner   int    `json:"owner"` // agent id (0 = admin)
	Name    string `json:"name"`
	Phone   string `json:"phone"`
	TgID    string `json:"tgId"`
	Note    string `json:"note"`
	Created int64  `json:"created"`
}

// RefundPolicy decides what a deleted account gives back to the wallets that paid for it.
type RefundPolicy struct {
	Mode       string `json:"mode"`       // "none", "window" (full refund if young and barely used), "prorated"
	Hours      int    `json:"hours"`      // window: account younger than this
	MaxUsedPct int    `json:"maxUsedPct"` // window: used less than this % of its quota
	Percent    int    `json:"percent"`    // share of the computed refund that is given back (100 = all)
}

type AgencySettings struct {
	Currency   string       `json:"currency"`
	PerGB      int64        `json:"perGB"` // the admin's prices for top-level agents
	PerDay     int64        `json:"perDay"`
	AddGB      int64        `json:"addGB"`
	AddDay     int64        `json:"addDay"`
	MaxLevels  int          `json:"maxLevels"` // agent levels below the admin (1 = no sub-agents)
	Refund     RefundPolicy `json:"refund"`
	LowBalance int64        `json:"lowBalance"` // notify when a wallet drops below this
	NotifySale bool         `json:"notifySale"` // tell the admin about every sale on Telegram
}

// MoveRequest asks the admin to move accounts from one agency to another.
type MoveRequest struct {
	ID      int      `json:"id"`
	From    int      `json:"from"`
	To      int      `json:"to"`
	Emails  []string `json:"emails"`
	Note    string   `json:"note"`
	T       int64    `json:"t"`
	Status  string   `json:"status"` // pending approved rejected
	Decided int64    `json:"decided,omitempty"`
	Reply   string   `json:"reply,omitempty"`
}

type agencyFile struct {
	Agents    map[string]*Agent    `json:"agents"`
	Plans     map[string]*Plan     `json:"plans"`
	Customers map[string]*Customer `json:"customers"`
	Requests  []*MoveRequest       `json:"requests"`
	Settings  AgencySettings       `json:"settings"`
	NextAgent int                  `json:"nextAgent"`
	NextPlan  int                  `json:"nextPlan"`
	NextCust  int                  `json:"nextCustomer"`
	NextReq   int                  `json:"nextRequest"`
}

// LedgerEntry is one wallet movement. Amt is signed (+ credit, - debit); Bal is the wallet
// balance right after it.
type LedgerEntry struct {
	ID     int64   `json:"id"`
	T      int64   `json:"t"`
	Agent  int     `json:"agent"`
	Amt    int64   `json:"amt"`
	Bal    int64   `json:"bal"`
	Kind   string  `json:"kind"`             // topup deduct transfer_in transfer_out sale renew addgb adddays reset refund reversal commission adjust
	Sale   int64   `json:"sale,omitempty"`   // groups the entries of one sale across the chain
	Seller int     `json:"seller,omitempty"` // the agent who made the sale (for chain entries)
	Acct   string  `json:"acct,omitempty"`
	GB     float64 `json:"gb,omitempty"`
	Days   float64 `json:"days,omitempty"`
	Plan   int     `json:"plan,omitempty"`
	Profit int64   `json:"profit,omitempty"` // for an ancestor: child's price - own price
	Svc    string  `json:"svc,omitempty"`    // protocols of the account ("openvpn,l2tp"), for reports
	Ref    int64   `json:"ref,omitempty"`    // entry this one undoes / refunds
	By     string  `json:"by"`               // "admin", "agent:7", "system", "api:7"
	IP     string  `json:"ip,omitempty"`
	Note   string  `json:"note,omitempty"`
}

type Activity struct {
	T      int64  `json:"t"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// ---------------------------------------------------------------- store

type AgencyStore struct {
	mu       sync.RWMutex
	dir      string
	f        agencyFile
	ledger   []LedgerEntry
	bal      map[int]int64
	lf       *os.File // ledger, append-only
	af       *os.File // activity log, append-only
	acts     []Activity
	nextTx   int64
	nextSale int64
}

// Ag is the agency store (nil when it could not be opened: the panel then runs without it).
var Ag *AgencyStore

func defaultAgencySettings() AgencySettings {
	return AgencySettings{Currency: "تومان", MaxLevels: 3, Refund: RefundPolicy{Mode: "none", Hours: 24, MaxUsedPct: 10, Percent: 100}}
}

func OpenAgency(dir string) (*AgencyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ag := &AgencyStore{dir: dir, bal: map[int]int64{}}
	ag.f = agencyFile{Agents: map[string]*Agent{}, Plans: map[string]*Plan{}, Customers: map[string]*Customer{},
		Settings: defaultAgencySettings(), NextAgent: 1, NextPlan: 1, NextCust: 1}
	if b, err := os.ReadFile(filepath.Join(dir, "agency.json")); err == nil {
		if err := json.Unmarshal(b, &ag.f); err != nil {
			return nil, fmt.Errorf("agency.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ag.fixup()
	if err := ag.loadLedger(); err != nil {
		return nil, err
	}
	var err error
	if ag.lf, err = os.OpenFile(filepath.Join(dir, "ledger.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		return nil, err
	}
	ag.af, _ = os.OpenFile(filepath.Join(dir, "activity.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	ag.loadActivity()
	return ag, nil
}

func (ag *AgencyStore) fixup() {
	if ag.f.Agents == nil {
		ag.f.Agents = map[string]*Agent{}
	}
	if ag.f.Plans == nil {
		ag.f.Plans = map[string]*Plan{}
	}
	if ag.f.Customers == nil {
		ag.f.Customers = map[string]*Customer{}
	}
	if ag.f.Settings.Currency == "" {
		ag.f.Settings.Currency = "تومان"
	}
	if ag.f.Settings.MaxLevels < 1 {
		ag.f.Settings.MaxLevels = 3
	}
	if ag.f.Settings.Refund.Mode == "" {
		ag.f.Settings.Refund = defaultAgencySettings().Refund
	}
	for _, a := range ag.f.Agents {
		if a.Pricing.Plans == nil {
			a.Pricing.Plans = map[string]PlanPrice{}
		}
		if a.ID >= ag.f.NextAgent {
			ag.f.NextAgent = a.ID + 1
		}
	}
	for _, p := range ag.f.Plans {
		if p.ID >= ag.f.NextPlan {
			ag.f.NextPlan = p.ID + 1
		}
	}
	for _, c := range ag.f.Customers {
		if c.ID >= ag.f.NextCust {
			ag.f.NextCust = c.ID + 1
		}
	}
	for _, q := range ag.f.Requests {
		if q.ID >= ag.f.NextReq {
			ag.f.NextReq = q.ID + 1
		}
	}
	if ag.f.NextReq < 1 {
		ag.f.NextReq = 1
	}
}

// loadLedger replays the ledger; balances are always the sum of the entries, never trusted
// from anywhere else. A torn last line (crash mid-write) is ignored.
func (ag *AgencyStore) loadLedger() error {
	f, err := os.Open(filepath.Join(ag.dir, "ledger.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e LedgerEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ID == 0 {
			continue
		}
		ag.ledger = append(ag.ledger, e)
		ag.bal[e.Agent] += e.Amt
		if e.ID >= ag.nextTx {
			ag.nextTx = e.ID
		}
		if e.Sale > ag.nextSale {
			ag.nextSale = e.Sale
		}
	}
	return nil
}

func (ag *AgencyStore) loadActivity() {
	b, err := os.ReadFile(filepath.Join(ag.dir, "activity.jsonl"))
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 5000 {
		lines = lines[len(lines)-5000:]
	}
	for _, l := range lines {
		var a Activity
		if json.Unmarshal([]byte(l), &a) == nil && a.T > 0 {
			ag.acts = append(ag.acts, a)
		}
	}
}

// saveLocked writes agency.json atomically. Callers hold ag.mu.
func (ag *AgencyStore) saveLocked() error {
	b, err := json.MarshalIndent(&ag.f, "", " ")
	if err != nil {
		return err
	}
	p := filepath.Join(ag.dir, "agency.json")
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// appendLocked durably adds entries (one write, one fsync) and only then updates the
// in-memory balances. If the write fails nothing changes. Callers hold ag.mu.
func (ag *AgencyStore) appendLocked(es []LedgerEntry) ([]LedgerEntry, error) {
	if ag.lf == nil {
		return nil, errors.New("wallet ledger is not available")
	}
	now := nowMs()
	var buf []byte
	bal := map[int]int64{}
	for i := range es {
		ag.nextTx++
		es[i].ID = ag.nextTx
		if es[i].T == 0 {
			es[i].T = now
		}
		b, ok := bal[es[i].Agent]
		if !ok {
			b = ag.bal[es[i].Agent]
		}
		b += es[i].Amt
		bal[es[i].Agent] = b
		es[i].Bal = b
		line, _ := json.Marshal(es[i])
		buf = append(append(buf, line...), '\n')
	}
	if _, err := ag.lf.Write(buf); err != nil {
		ag.nextTx -= int64(len(es))
		return nil, err
	}
	if err := ag.lf.Sync(); err != nil {
		return nil, err
	}
	for id, b := range bal {
		ag.bal[id] = b
	}
	ag.ledger = append(ag.ledger, es...)
	return es, nil
}

func (ag *AgencyStore) logLocked(actor, action, target, ip, format string, args ...any) {
	a := Activity{T: nowMs(), Actor: actor, Action: action, Target: target, IP: ip, Detail: fmt.Sprintf(format, args...)}
	ag.acts = append(ag.acts, a)
	if len(ag.acts) > 6000 {
		ag.acts = append([]Activity(nil), ag.acts[len(ag.acts)-5000:]...)
	}
	if ag.af != nil {
		b, _ := json.Marshal(a)
		ag.af.Write(append(b, '\n'))
	}
}

func (ag *AgencyStore) Log(actor, action, target, ip, format string, args ...any) {
	ag.mu.Lock()
	ag.logLocked(actor, action, target, ip, format, args...)
	ag.mu.Unlock()
}

func (ag *AgencyStore) Close() {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if ag.lf != nil {
		ag.lf.Close()
		ag.lf = nil
	}
	if ag.af != nil {
		ag.af.Close()
		ag.af = nil
	}
}

// ---------------------------------------------------------------- tree

func (ag *AgencyStore) agentLocked(id int) *Agent { return ag.f.Agents[strconv.Itoa(id)] }

func (ag *AgencyStore) Agent(id int) (Agent, bool) {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	a := ag.agentLocked(id)
	if a == nil {
		return Agent{}, false
	}
	return *a, true
}

// chainLocked is [id, parent, grandparent, ...] up to a top-level agent.
func (ag *AgencyStore) chainLocked(id int) []*Agent {
	var out []*Agent
	seen := map[int]bool{}
	for id > 0 && !seen[id] {
		seen[id] = true
		a := ag.agentLocked(id)
		if a == nil {
			break
		}
		out = append(out, a)
		id = a.Parent
	}
	return out
}

func (ag *AgencyStore) levelLocked(id int) int { return len(ag.chainLocked(id)) }

// isUnderLocked: is id inside the subtree of root (root itself included)? root 0 = everything.
func (ag *AgencyStore) isUnderLocked(id, root int) bool {
	if root == 0 {
		return true
	}
	for _, a := range ag.chainLocked(id) {
		if a.ID == root {
			return true
		}
	}
	return false
}

func (ag *AgencyStore) childrenLocked(parent int) []*Agent {
	var out []*Agent
	for _, a := range ag.f.Agents {
		if a.Parent == parent {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// subtreeLocked lists root and everything below it.
func (ag *AgencyStore) subtreeLocked(root int) map[int]bool {
	out := map[int]bool{}
	for _, a := range ag.f.Agents {
		if ag.isUnderLocked(a.ID, root) {
			out[a.ID] = true
		}
	}
	return out
}

// activeReason is "" when the agent may act now, else why not.
func (a *Agent) activeReason(now int64) string {
	switch {
	case !a.Enable:
		return "agency disabled"
	case a.BanUntil == -1 || a.BanUntil > now:
		return "agency suspended"
	case a.Expiry > 0 && a.Expiry <= now:
		return "agency expired"
	}
	return ""
}

// chainActiveLocked: an agent can act only while it and every ancestor are active.
func (ag *AgencyStore) chainActiveLocked(id int) string {
	now := nowMs()
	ch := ag.chainLocked(id)
	if len(ch) == 0 {
		return "unknown agent"
	}
	for i, a := range ch {
		if why := a.activeReason(now); why != "" {
			if i > 0 {
				return "parent " + why
			}
			return why
		}
	}
	return ""
}

// ---------------------------------------------------------------- auth

func (ag *AgencyStore) Authenticate(user, pass string) (*Agent, string) {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	for _, a := range ag.f.Agents {
		if !strings.EqualFold(a.Username, user) {
			continue
		}
		i := strings.IndexByte(a.Hash, '$')
		if i < 0 || subtle.ConstantTimeCompare([]byte(hashPass(a.Hash[:i], pass)), []byte(a.Hash)) != 1 {
			return nil, "Wrong username or password"
		}
		if why := ag.chainActiveLocked(a.ID); why != "" {
			return nil, why
		}
		cp := *a
		return &cp, ""
	}
	return nil, "Wrong username or password"
}

// SessionOK: the agent still exists, is active, and the session was issued for its current
// token version (a password change or a ban ends all sessions).
func (ag *AgencyStore) SessionOK(id, ver int) bool {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	a := ag.agentLocked(id)
	return a != nil && a.TokenVer == ver && ag.chainActiveLocked(id) == ""
}

func newAPIKey() (id, key string) {
	b := make([]byte, 24)
	rand.Read(b)
	key = "vl_" + hex.EncodeToString(b)
	return key[3:11], key
}

// APIAgent resolves an API key; it also enforces the agent's IP allowlist. rate is the
// agent's allowed requests per minute.
func (ag *AgencyStore) APIAgent(key, ip string) (id, rate int, why string) {
	if !strings.HasPrefix(key, "vl_") || len(key) < 20 {
		return 0, 0, "bad API key"
	}
	ag.mu.Lock()
	defer ag.mu.Unlock()
	for _, a := range ag.f.Agents {
		for i := range a.APIKeys {
			k := &a.APIKeys[i]
			if k.ID != key[3:11] {
				continue
			}
			j := strings.IndexByte(k.Hash, '$')
			if j < 0 || subtle.ConstantTimeCompare([]byte(hashPass(k.Hash[:j], key)), []byte(k.Hash)) != 1 {
				return 0, 0, "bad API key"
			}
			if !a.Perms.API {
				return 0, 0, "API access is not enabled for this agency"
			}
			if why := ag.chainActiveLocked(a.ID); why != "" {
				return 0, 0, why
			}
			if len(a.APIAllow) > 0 && !containsStr(a.APIAllow, ip) {
				return 0, 0, "this IP may not use the API key"
			}
			k.LastUse = nowMs()
			rate := a.APIRate
			if rate <= 0 {
				rate = 120
			}
			return a.ID, rate, ""
		}
	}
	return 0, 0, "bad API key"
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if strings.TrimSpace(x) == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- pricing

type pricesEff struct {
	PerGB  int64 `json:"perGB"`
	PerDay int64 `json:"perDay"`
	AddGB  int64 `json:"addGB"`
	AddDay int64 `json:"addDay"`
}

// chargeKinds are the ledger kinds that pay for something sold.
var chargeKinds = map[string]bool{"sale": true, "renew": true, "addgb": true, "adddays": true, "reset": true}

// effPricesLocked resolves an agent's per-unit prices: unset (0) values are inherited from the
// parent's own resolved prices; top-level agents inherit the admin's settings.
func (ag *AgencyStore) effPricesLocked(id int) pricesEff {
	s := ag.f.Settings
	base := pricesEff{PerGB: s.PerGB, PerDay: s.PerDay}
	base.AddGB, base.AddDay = s.AddGB, s.AddDay
	if base.AddGB == 0 {
		base.AddGB = base.PerGB
	}
	if base.AddDay == 0 {
		base.AddDay = base.PerDay
	}
	ch := ag.chainLocked(id)
	for i := len(ch) - 1; i >= 0; i-- { // from the top-level agent down to id
		p := ch[i].Pricing
		cur := base
		if p.PerGB > 0 {
			cur.PerGB = p.PerGB
		}
		if p.PerDay > 0 {
			cur.PerDay = p.PerDay
		}
		cur.AddGB, cur.AddDay = base.AddGB, base.AddDay
		if p.PerGB > 0 {
			cur.AddGB = p.PerGB
		}
		if p.PerDay > 0 {
			cur.AddDay = p.PerDay
		}
		if p.AddGB > 0 {
			cur.AddGB = p.AddGB
		}
		if p.AddDay > 0 {
			cur.AddDay = p.AddDay
		}
		base = cur
	}
	return base
}

// planPriceLocked is what agent id pays for plan p (renew picks the renewal price).
func (ag *AgencyStore) planPriceLocked(id int, p *Plan, renew bool) int64 {
	price := p.Price
	if renew && p.Renew > 0 {
		price = p.Renew
	}
	key := strconv.Itoa(p.ID)
	ch := ag.chainLocked(id)
	for i := len(ch) - 1; i >= 0; i-- {
		pp := ch[i].Pricing.Plans[key]
		if renew && pp.Renew > 0 {
			price = pp.Renew
		} else if pp.Sell > 0 {
			price = pp.Sell
		}
	}
	return price
}

// Quote describes what is being bought.
type Quote struct {
	Kind   string  `json:"kind"`   // sale, renew, addgb, adddays, reset
	Plan   int     `json:"plan"`   // sale/renew by plan
	GB     float64 `json:"gb"`     // quota bought (sale, addgb, reset)
	DaysMs int64   `json:"daysMs"` // time bought, in ms (sale, adddays)
}

func (q Quote) days() float64 { return float64(q.DaysMs) / dayMs }

func discount(v int64, pct int) int64 {
	if pct <= 0 {
		return v
	}
	if pct >= 100 {
		return 0
	}
	return v * int64(100-pct) / 100
}

// priceLocked is what agent id pays for q.
func (ag *AgencyStore) priceLocked(id int, q Quote) (int64, error) {
	a := ag.agentLocked(id)
	if a == nil {
		return 0, errors.New("unknown agent")
	}
	var v int64
	if q.Plan > 0 {
		p := ag.f.Plans[strconv.Itoa(q.Plan)]
		if p == nil || !p.Enable {
			return 0, errors.New("plan not found")
		}
		v = ag.planPriceLocked(id, p, q.Kind == "renew")
	} else {
		e := ag.effPricesLocked(id)
		gb, days := e.PerGB, e.PerDay
		if q.Kind != "sale" {
			gb, days = e.AddGB, e.AddDay
		}
		v = int64(math.Round(float64(gb)*q.GB + float64(days)*q.days()))
	}
	return discount(v, a.Pricing.Discount), nil
}

// MatchPlan is matchPlanLocked for callers without the lock (0 = no plan matches).
func (ag *AgencyStore) MatchPlan(gb float64, durMs int64) int {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	if p := ag.matchPlanLocked(gb, durMs); p != nil {
		return p.ID
	}
	return 0
}

// matchPlanLocked finds an enabled plan with exactly this quota and time (the bot sells by GB
// and days; if that is one of the plans, the plan's price applies).
func (ag *AgencyStore) matchPlanLocked(gb float64, durMs int64) *Plan {
	for _, p := range ag.f.Plans {
		if !p.Enable {
			continue
		}
		if math.Abs(p.GB-gb) < 0.01 && math.Abs(p.Days*dayMs-float64(durMs)) < 3600000 {
			return p
		}
	}
	return nil
}

// ---------------------------------------------------------------- charging

// ChargeMeta is the context recorded on every ledger entry of a charge.
type ChargeMeta struct {
	By, IP, Acct, Note, Svc string
}

// chargeLocked takes q's price from the seller and from every ancestor, all or nothing.
// It returns the sale id grouping the entries. The seller always gets an entry, even a free one,
// so every sale is on record.
func (ag *AgencyStore) chargeLocked(seller int, q Quote, m ChargeMeta) (int64, int64, error) {
	if why := ag.chainActiveLocked(seller); why != "" {
		return 0, 0, errors.New(why)
	}
	ch := ag.chainLocked(seller)
	prices := make([]int64, len(ch))
	for i, a := range ch {
		p, err := ag.priceLocked(a.ID, q)
		if err != nil {
			return 0, 0, err
		}
		if p < 0 {
			p = 0
		}
		prices[i] = p
		limit := a.Limits.CreditLimit
		if a.Limits.MaxDebt > limit {
			limit = a.Limits.MaxDebt
		}
		if p > 0 && ag.bal[a.ID]-p < -limit {
			if i == 0 {
				return 0, 0, fmt.Errorf("insufficient balance: this costs %d %s, wallet has %d", p, ag.f.Settings.Currency, ag.bal[a.ID])
			}
			return 0, 0, errors.New("insufficient balance in the parent agency's wallet")
		}
	}
	ag.nextSale++
	sale := ag.nextSale
	kind := q.Kind
	var es []LedgerEntry
	for i, a := range ch {
		if prices[i] == 0 && i > 0 {
			continue
		}
		e := LedgerEntry{Agent: a.ID, Amt: -prices[i], Kind: kind, Sale: sale, Seller: seller, Acct: m.Acct,
			GB: q.GB, Days: math.Round(q.days()*1000) / 1000, Plan: q.Plan, By: m.By, IP: m.IP, Note: m.Note, Svc: m.Svc}
		if i > 0 {
			e.Profit = prices[i-1] - prices[i]
		}
		es = append(es, e)
	}
	if _, err := ag.appendLocked(es); err != nil {
		ag.nextSale--
		return 0, 0, err
	}
	return sale, prices[0], nil
}

// reverseLocked undoes a whole sale (used when the core refused the change after the charge).
func (ag *AgencyStore) reverseLocked(sale int64, by, why string) {
	if sale == 0 {
		return
	}
	var es []LedgerEntry
	for _, e := range ag.ledger {
		if e.Sale == sale && chargeKinds[e.Kind] {
			es = append(es, LedgerEntry{Agent: e.Agent, Amt: -e.Amt, Kind: "reversal", Sale: sale, Seller: e.Seller,
				Acct: e.Acct, Ref: e.ID, By: by, Note: why})
		}
	}
	if len(es) > 0 {
		ag.appendLocked(es)
	}
}

// Charge is the locked wrapper used by the API: price, limits and payment in one step.
func (ag *AgencyStore) Charge(seller int, q Quote, m ChargeMeta) (int64, int64, error) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.chargeLocked(seller, q, m)
}

func (ag *AgencyStore) Reverse(sale int64, by, why string) {
	ag.mu.Lock()
	ag.reverseLocked(sale, by, why)
	ag.mu.Unlock()
}

// refundLocked gives back what an account cost, by the refund policy. used/total are the
// account's traffic, created its creation time. Already refunded entries are skipped, and so are
// entries older than the account (an earlier account that had the same name). An account that
// is already expired or used up gives nothing back.
func (ag *AgencyStore) refundLocked(acct string, created, used, total, expiry int64, by string) int64 {
	pol := ag.f.Settings.Refund
	if pol.Mode == "" || pol.Mode == "none" || pol.Percent <= 0 {
		return 0
	}
	now := nowMs()
	if (expiry > 0 && expiry <= now) || (total > 0 && used >= total) {
		return 0
	}
	frac := 0.0
	switch pol.Mode {
	case "window":
		young := pol.Hours <= 0 || now-created <= int64(pol.Hours)*3600000
		lightly := total <= 0 || pol.MaxUsedPct <= 0 || float64(used)*100 < float64(total)*float64(pol.MaxUsedPct)
		if young && lightly {
			frac = 1
		}
	case "prorated": // what is left of the account: the smaller of quota left and time left
		frac = 1
		if total > 0 {
			frac = math.Min(frac, math.Max(0, 1-float64(used)/float64(total)))
		}
		if expiry > 0 && expiry > created {
			frac = math.Min(frac, math.Max(0, math.Min(1, float64(expiry-now)/float64(expiry-created))))
		}
	}
	frac *= float64(pol.Percent) / 100
	if frac <= 0 {
		return 0
	}
	done := map[int64]bool{}
	for _, e := range ag.ledger {
		if (e.Kind == "refund" || e.Kind == "reversal") && e.Ref > 0 {
			done[e.Ref] = true
		}
	}
	var es []LedgerEntry
	var mine int64
	for _, e := range ag.ledger {
		if !strings.EqualFold(e.Acct, acct) || e.Amt >= 0 || done[e.ID] || e.Sale == 0 || (created > 0 && e.T < created-60000) {
			continue
		}
		back := int64(math.Round(float64(-e.Amt) * frac))
		if back <= 0 {
			continue
		}
		es = append(es, LedgerEntry{Agent: e.Agent, Amt: back, Kind: "refund", Sale: e.Sale, Seller: e.Seller, Acct: acct, Ref: e.ID, By: by,
			Note: fmt.Sprintf("%s refund %.0f%%", pol.Mode, frac*100)})
		if e.Agent == e.Seller {
			mine += back
		}
	}
	if len(es) > 0 {
		if _, err := ag.appendLocked(es); err != nil {
			return 0
		}
	}
	return mine
}

func (ag *AgencyStore) Refund(acct string, created, used, total, expiry int64, by string) int64 {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.refundLocked(acct, created, used, total, expiry, by)
}

// Credit moves money into a wallet (top-up by the admin or a parent, adjustments, commission).
func (ag *AgencyStore) Credit(agent int, amt int64, kind, by, ip, note string) (LedgerEntry, error) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if ag.agentLocked(agent) == nil {
		return LedgerEntry{}, errors.New("unknown agent")
	}
	es, err := ag.appendLocked([]LedgerEntry{{Agent: agent, Amt: amt, Kind: kind, By: by, IP: ip, Note: note}})
	if err != nil {
		return LedgerEntry{}, err
	}
	ag.logLocked(by, "wallet:"+kind, "agent:"+strconv.Itoa(agent), ip, "%+d %s", amt, note)
	return es[0], nil
}

// Transfer moves credit between two wallets in one durable write.
func (ag *AgencyStore) Transfer(from, to int, amt int64, by, ip, note string) error {
	if amt <= 0 {
		return errors.New("amount must be positive")
	}
	ag.mu.Lock()
	defer ag.mu.Unlock()
	fa, ta := ag.agentLocked(from), ag.agentLocked(to)
	if fa == nil || ta == nil {
		return errors.New("unknown agent")
	}
	limit := fa.Limits.CreditLimit
	if ag.bal[from]-amt < -limit {
		return errors.New("insufficient balance")
	}
	_, err := ag.appendLocked([]LedgerEntry{
		{Agent: from, Amt: -amt, Kind: "transfer_out", By: by, IP: ip, Note: fmt.Sprintf("to #%d %s", to, note)},
		{Agent: to, Amt: amt, Kind: "transfer_in", By: by, IP: ip, Note: fmt.Sprintf("from #%d %s", from, note)},
	})
	if err == nil {
		ag.logLocked(by, "wallet:transfer", fmt.Sprintf("agent:%d->%d", from, to), ip, "%d %s", amt, note)
	}
	return err
}

func (ag *AgencyStore) Balance(id int) int64 {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	return ag.bal[id]
}

// ---------------------------------------------------------------- limits

// SaleCheck is everything a limit check needs to know about the seller's accounts; the
// caller collects it from the core store.
type SaleCheck struct {
	Owned, Active int     // accounts the seller owns now / that are usable now
	GB            float64 // quota being sold or added (0 = unlimited for a new account)
	TotalGB       float64 // the account's quota after the change (for the per-account maximum)
	DaysMs        int64   // time being sold (0 = unlimited)
	Inbounds      []int
	Devices       int
	New           bool // a new account (counts toward customers and daily creates)
	Today         int  // accounts the seller created today
}

// allowedInboundsLocked: the services an agent may sell (nil = all): the agent's own list
// narrowed by every ancestor's.
func (ag *AgencyStore) allowedInboundsLocked(id int) map[int]bool {
	var out map[int]bool
	for _, a := range ag.chainLocked(id) {
		if len(a.Limits.Inbounds) == 0 {
			continue
		}
		set := map[int]bool{}
		for _, x := range a.Limits.Inbounds {
			if out == nil || out[x] {
				set[x] = true
			}
		}
		out = set
	}
	return out
}

func (ag *AgencyStore) soldGBLocked(id int) float64 {
	var gb float64
	reversed := map[int64]bool{}
	for _, e := range ag.ledger {
		if e.Agent == id && e.Kind == "reversal" {
			reversed[e.Sale] = true
		}
	}
	for _, e := range ag.ledger {
		if e.Agent == id && e.Seller == id && chargeKinds[e.Kind] && e.Kind != "adddays" && !reversed[e.Sale] {
			gb += e.GB
		}
	}
	return gb
}

// checkLocked enforces the seller's permissions and limits for c. perm names the permission
// the operation needs.
func (ag *AgencyStore) checkLocked(id int, perm string, c SaleCheck) error {
	a := ag.agentLocked(id)
	if a == nil {
		return errors.New("unknown agent")
	}
	if why := ag.chainActiveLocked(id); why != "" {
		return errors.New(why)
	}
	p := a.Perms
	allowed := map[string]bool{"create": p.Create, "renew": p.Renew, "reset": p.Reset, "delete": p.Delete,
		"suspend": p.Suspend, "edit": p.Edit, "bulk": p.Bulk}[perm]
	if !allowed {
		return fmt.Errorf("your agency may not do this (%s)", perm)
	}
	L := a.Limits
	if c.New {
		if L.MaxCustomers > 0 && c.Owned >= L.MaxCustomers {
			return fmt.Errorf("customer limit reached (%d)", L.MaxCustomers)
		}
		if L.MaxActive > 0 && c.Active >= L.MaxActive {
			return fmt.Errorf("active account limit reached (%d)", L.MaxActive)
		}
		if L.MaxDailyCreates > 0 && c.Today >= L.MaxDailyCreates {
			return fmt.Errorf("daily limit of new accounts reached (%d)", L.MaxDailyCreates)
		}
	}
	if c.New || perm == "renew" {
		if (c.New && c.GB == 0 || c.New && c.DaysMs == 0) && !p.Unlimited {
			return errors.New("your agency may not sell unlimited quota or time")
		}
		tot := c.TotalGB
		if tot == 0 {
			tot = c.GB
		}
		if L.MaxGB > 0 && tot > L.MaxGB+1e-9 {
			return fmt.Errorf("at most %.0f GB per account", L.MaxGB)
		}
		if L.MaxDays > 0 && c.DaysMs > int64(L.MaxDays)*dayMs+3600000 {
			return fmt.Errorf("at most %d days at a time", L.MaxDays)
		}
		if L.MaxSoldGB > 0 && ag.soldGBLocked(id)+c.GB > L.MaxSoldGB+1e-9 {
			return fmt.Errorf("total sold volume limit reached (%.0f GB)", L.MaxSoldGB)
		}
	}
	if allow := ag.allowedInboundsLocked(id); allow != nil {
		for _, x := range c.Inbounds {
			if !allow[x] {
				return fmt.Errorf("your agency may not sell service #%d", x)
			}
		}
	}
	if L.MaxDevices > 0 && c.Devices > L.MaxDevices {
		return fmt.Errorf("at most %d simultaneous connections per account", L.MaxDevices)
	}
	return nil
}

func (ag *AgencyStore) Check(id int, perm string, c SaleCheck) error {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	return ag.checkLocked(id, perm, c)
}

// ---------------------------------------------------------------- backup

type agencyExport struct {
	File   agencyFile    `json:"file"`
	Ledger []LedgerEntry `json:"ledger"`
}

func (ag *AgencyStore) Export() agencyExport {
	ag.mu.RLock()
	defer ag.mu.RUnlock()
	return agencyExport{File: ag.f, Ledger: append([]LedgerEntry(nil), ag.ledger...)}
}

// Import replaces everything with a backup (the ledger file is rewritten from it).
func (ag *AgencyStore) Import(x agencyExport) error {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	p := filepath.Join(ag.dir, "ledger.jsonl")
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range x.Ledger {
		b, _ := json.Marshal(e)
		w.Write(append(b, '\n'))
	}
	if err = w.Flush(); err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		return err
	}
	if ag.lf != nil {
		ag.lf.Close()
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	ag.f = x.File
	ag.fixup()
	ag.ledger, ag.bal, ag.nextTx, ag.nextSale = nil, map[int]int64{}, 0, 0
	if err := ag.loadLedger(); err != nil {
		return err
	}
	if ag.lf, err = os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		return err
	}
	return ag.saveLocked()
}
