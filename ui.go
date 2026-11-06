package main

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

// failed-login throttle: 8 tries per 5 minutes per remote address
var (
	loginMu    sync.Mutex
	loginTries = map[string][]int64{}
)

func loginAllowed(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	cut := nowMs() - 5*60*1000
	v := loginTries[ip][:0]
	for _, t := range loginTries[ip] {
		if t > cut {
			v = append(v, t)
		}
	}
	loginTries[ip] = v
	return len(v) < 8
}
func loginFailed(ip string) {
	loginMu.Lock()
	loginTries[ip] = append(loginTries[ip], nowMs())
	loginMu.Unlock()
}

func (a *API) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Write(indexHTML)
}

// ui guards the panel's own JSON endpoints: an honest 401 (the page needs to show the login form).
func (a *API) ui(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.st.loggedIn(r) {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, envelope{false, "login required", nil})
			return
		}
		r.ParseForm()
		h(w, r)
	}
}

func (a *API) uiRoutes(mux *http.ServeMux) {
	u := func(m, p string, h http.HandlerFunc) { mux.HandleFunc(m+" /panel/ui"+p, a.ui(h)) }
	u("GET", "/summary", a.uiSummary)
	u("GET", "/accounts", a.uiAccounts)
	u("POST", "/bulk", a.uiBulk)
	u("POST", "/bulkCreate", a.uiBulkCreate)
	u("GET", "/sessions", a.uiSessions)
	u("POST", "/kick", a.uiKick)
	u("GET", "/events", a.uiEvents)
	u("GET", "/settings", a.uiGetSettings)
	u("POST", "/settings", a.uiSetSettings)
	u("POST", "/password", a.uiPassword)
	u("POST", "/certs/{id}", a.uiCerts)
	u("POST", "/certIssue/{id}", a.uiCertIssue)
	u("GET", "/certStatus/{id}", a.uiCertStatus)
	u("GET", "/backup", a.uiBackup)
	u("GET", "/updateCheck", a.uiUpdateCheck)
	u("POST", "/update", a.uiUpdate)
	u("POST", "/reboot", a.uiReboot)
	u("POST", "/restart", a.uiRestart)
	u("POST", "/restore", a.uiRestore)
	u("POST", "/backupNow", a.uiBackupNow)
	u("POST", "/import", a.uiImport)
}

type accountRow struct {
	Email      string `json:"email"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	SubID      string `json:"subId"`
	Inbounds   []int  `json:"inbounds"`
	Enable     bool   `json:"enable"`
	Total      int64  `json:"total"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	Expiry     int64  `json:"expiry"`
	LimitIP    int    `json:"limitIp"`
	SpeedDown  int    `json:"speedDown"`
	SpeedUp    int    `json:"speedUp"`
	Single     bool   `json:"singleProto"`
	Reset      int    `json:"reset"`
	Comment    string `json:"comment"`
	Online     int    `json:"online"`
	LastOnline int64  `json:"lastOnline"`
	Status     string `json:"status"`
}

func statusOf(a *Account, now int64) string {
	switch {
	case !a.Enable:
		return "disabled"
	case a.expired(now):
		return "expired"
	case a.overQuota():
		return "depleted"
	}
	return "active"
}

func onlineCounts() map[string]int {
	m := map[string]int{}
	for _, s := range Sessions.Snapshot() {
		m[strings.ToLower(s.Email)]++
	}
	return m
}

func (a *API) uiAccounts(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.Form.Get("q")))
	inb, _ := strconv.Atoi(r.Form.Get("inbound"))
	status := r.Form.Get("status")
	sortBy := r.Form.Get("sort")
	page, _ := strconv.Atoi(r.Form.Get("page"))
	size, _ := strconv.Atoi(r.Form.Get("size"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	on := onlineCounts()
	now := nowMs()
	a.st.mu.RLock()
	rows := make([]accountRow, 0, 64)
	for _, acc := range a.st.st.Accounts {
		st := statusOf(acc, now)
		if inb > 0 && !hasInt(acc.Inbounds, inb) {
			continue
		}
		o := on[strings.ToLower(acc.Email)]
		switch status {
		case "":
		case "online":
			if o == 0 {
				continue
			}
		default:
			if st != status {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(acc.Email), q) && !strings.Contains(strings.ToLower(acc.Username), q) &&
			!strings.Contains(strings.ToLower(acc.Comment), q) {
			continue
		}
		rows = append(rows, accountRow{Email: acc.Email, Username: acc.Username, Password: acc.Password, SubID: acc.SubID,
			Inbounds: append([]int(nil), acc.Inbounds...), Enable: acc.Enable, Total: acc.TotalGB, Up: acc.Up, Down: acc.Down,
			Expiry: acc.ExpiryTime, LimitIP: acc.LimitIP, SpeedDown: acc.SpeedDown, SpeedUp: acc.SpeedUp, Single: acc.SingleProto, Reset: acc.Reset,
			Comment: acc.Comment, Online: o, LastOnline: acc.LastOnline, Status: st})
	}
	a.st.mu.RUnlock()
	less := map[string]func(i, j int) bool{
		"used": func(i, j int) bool { return rows[i].Up+rows[i].Down > rows[j].Up+rows[j].Down },
		"expiry": func(i, j int) bool {
			return rows[i].Expiry != 0 && (rows[j].Expiry == 0 || rows[i].Expiry < rows[j].Expiry)
		},
		"last": func(i, j int) bool { return rows[i].LastOnline > rows[j].LastOnline },
	}
	f := less[sortBy]
	if f == nil {
		f = func(i, j int) bool { return rows[i].Email < rows[j].Email }
	}
	sort.Slice(rows, f)
	total := len(rows)
	lo := (page - 1) * size
	if lo > total {
		lo = total
	}
	hi := lo + size
	if hi > total {
		hi = total
	}
	ok(w, "", map[string]any{"total": total, "page": page, "size": size, "items": rows[lo:hi]})
}

func (a *API) uiSummary(w http.ResponseWriter, r *http.Request) {
	now := nowMs()
	cnt := map[string]int{}
	var used int64
	a.st.mu.RLock()
	for _, acc := range a.st.st.Accounts {
		cnt[statusOf(acc, now)]++
		used += acc.Up + acc.Down
	}
	type inb struct {
		ID       int    `json:"id"`
		Remark   string `json:"remark"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Enable   bool   `json:"enable"`
		Members  int    `json:"members"`
		Online   int    `json:"online"`
		Domain   string `json:"domain"`
		PSK      string `json:"psk,omitempty"`
	}
	ins := []inb{}
	for _, in := range a.st.sortedInbounds() {
		ins = append(ins, inb{ID: in.ID, Remark: in.Remark, Protocol: in.Protocol, Port: in.Port, Enable: in.Enable,
			Members: len(a.st.membersLocked(in.ID)), Domain: strings.TrimSpace(strSetting(in.Settings, "connDomain", "")), PSK: l2tpPSK(in)})
	}
	n := len(a.st.st.Accounts)
	a.st.mu.RUnlock()
	byIn := map[int]int{}
	sess := Sessions.Snapshot()
	users := map[string]bool{}
	for _, s := range sess {
		byIn[s.InboundID]++
		users[strings.ToLower(s.Email)] = true
	}
	for i := range ins {
		ins[i].Online = byIn[ins[i].ID]
	}
	ok(w, "", map[string]any{"accounts": n, "status": cnt, "usedBytes": used, "sessions": len(sess),
		"onlineUsers": len(users), "inbounds": ins, "sys": readSys()})
}

func (a *API) uiSessions(w http.ResponseWriter, r *http.Request) {
	type row struct {
		ID, Email, Proto, SrcIP, VIP string
		InboundID                    int
		Start                        int64
		Up, Down                     int64
	}
	var out []row
	for _, s := range Sessions.Snapshot() {
		out = append(out, row{s.ID, s.Email, s.Proto, s.SrcIP, s.VIP, s.InboundID, s.Start, s.Up, s.Down})
	}
	ok(w, "", out)
}

func (a *API) uiKick(w http.ResponseWriter, r *http.Request) {
	if id := r.Form.Get("id"); id != "" {
		if s := Sessions.Get(id); s != nil && s.Kill != nil {
			s.Kill()
			Events.Add("kick", s.Proto, s.Email, "disconnected by admin")
			ok(w, "ok", 1)
			return
		}
		fail(w, "session not found")
		return
	}
	n := Sessions.KickEmail(r.Form.Get("email"))
	Events.Add("kick", "", r.Form.Get("email"), "disconnected by admin (%d sessions)", n)
	ok(w, "ok", n)
}

func (a *API) uiEvents(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.Form.Get("n"))
	if n < 1 || n > 1000 {
		n = 200
	}
	ok(w, "", Events.Recent(n, r.Form.Get("email"), r.Form.Get("kind")))
}

// ---------------------------------------------------------------- bulk

func (a *API) uiBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string   `json:"action"`
		Emails []string `json:"emails"`
		Days   int      `json:"days"`
		GB     float64  `json:"gb"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Emails) == 0 {
		fail(w, "bad request")
		return
	}
	n := 0
	var kick []string
	var reload []int
	a.st.mu.Lock()
	for _, e := range req.Emails {
		acc := a.st.st.Accounts[ekey(e)]
		if acc == nil {
			continue
		}
		n++
		switch req.Action {
		case "enable":
			acc.Enable = true
		case "disable":
			acc.Enable = false
			kick = append(kick, acc.Email)
		case "reset":
			acc.Up, acc.Down = 0, 0
		case "extend":
			if req.Days > 0 {
				base := acc.ExpiryTime
				if base < nowMs() {
					base = nowMs()
				}
				acc.ExpiryTime = base + int64(req.Days)*86400000
			}
			if req.GB > 0 && acc.TotalGB > 0 {
				acc.TotalGB += int64(req.GB * 1073741824)
			}
		case "delete":
			delete(a.st.st.Accounts, ekey(e))
			kick = append(kick, acc.Email)
			reload = append(reload, acc.Inbounds...)
		default:
			a.st.mu.Unlock()
			fail(w, "unknown action")
			return
		}
	}
	a.st.touch()
	a.st.mu.Unlock()
	for _, e := range kick {
		a.d.Kick(e)
	}
	for _, id := range unionInts(reload, nil) {
		a.d.ReloadInbound(id)
	}
	ok(w, "done", n)
}

func randPass(n int) string {
	const al = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = al[int(b[i])%len(al)]
	}
	return string(b)
}

func (a *API) uiBulkCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prefix    string  `json:"prefix"`
		Count     int     `json:"count"`
		Inbounds  []int   `json:"inbounds"`
		GB        float64 `json:"gb"`
		Days      int     `json:"days"`
		LimitIP   int     `json:"limitIp"`
		SpeedDown int     `json:"speedDown"`
		SpeedUp   int     `json:"speedUp"`
		PassLen   int     `json:"passLen"`
		Single    bool    `json:"singleProto"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Count < 1 || req.Count > 1000 || len(req.Inbounds) == 0 {
		fail(w, "bad request")
		return
	}
	if req.PassLen < 6 {
		req.PassLen = 10
	}
	prefix := strings.TrimSpace(req.Prefix)
	if prefix == "" {
		prefix = "u"
	}
	a.st.mu.Lock()
	for _, id := range req.Inbounds {
		if a.st.st.Inbounds[id] == nil {
			a.st.mu.Unlock()
			fail(w, "inbound not found: "+itoa(id))
			return
		}
	}
	if msg := a.st.checkSameProtoLocked(req.Inbounds); msg != "" {
		a.st.mu.Unlock()
		fail(w, msg)
		return
	}
	type made struct{ User, Pass string }
	var out []made
	exp := int64(0)
	if req.Days > 0 {
		exp = nowMs() + int64(req.Days)*86400000
	}
	n := 0
	for i := 1; len(out) < req.Count && n < 100000; i++ {
		n++
		name := fmt.Sprintf("%s%d", prefix, i)
		taken := a.st.st.Accounts[ekey(name)] != nil
		if !taken {
			for _, o := range a.st.st.Accounts {
				if strings.EqualFold(o.Username, name) {
					taken = true
					break
				}
			}
		}
		if taken {
			continue
		}
		pw := randPass(req.PassLen)
		a.st.st.Accounts[ekey(name)] = &Account{Email: name, Username: name, Password: pw, SubID: newSubID(), Enable: true,
			TotalGB: int64(req.GB * 1073741824), ExpiryTime: exp, LimitIP: req.LimitIP, SpeedDown: req.SpeedDown,
			SpeedUp: req.SpeedUp, SingleProto: req.Single, Inbounds: append([]int(nil), req.Inbounds...), CreatedAt: nowMs()}
		out = append(out, made{name, pw})
	}
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "created", out)
}

// ---------------------------------------------------------------- settings

func (a *API) uiGetSettings(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	g := a.st.st.Global
	user := a.st.st.Admin.User
	a.st.mu.RUnlock()
	ok(w, "", map[string]any{"global": g, "admin": user})
}

func (a *API) uiSetSettings(w http.ResponseWriter, r *http.Request) {
	var g GlobalSettings
	if json.NewDecoder(r.Body).Decode(&g) != nil {
		fail(w, "bad request")
		return
	}
	if g.LimitStrategy != "reject" && g.LimitStrategy != "evict" {
		fail(w, "limitStrategy must be reject or evict")
		return
	}
	if g.EvictGraceSec < 0 || g.EvictGraceSec > 3600 {
		fail(w, "evictGraceSec out of range")
		return
	}
	bp := g.BasePath
	if bp == "" {
		bp = "/"
	}
	if !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}
	if !strings.HasSuffix(bp, "/") {
		bp += "/"
	}
	a.st.mu.Lock()
	cur := &a.st.st.Global
	cur.LimitStrategy, cur.EvictGraceSec = g.LimitStrategy, g.EvictGraceSec
	cur.DefaultSingleProto = g.DefaultSingleProto
	if g.SessionMinutes > 0 {
		cur.SessionMinutes = g.SessionMinutes
	}
	cur.TgToken, cur.TgChat, cur.TgNoLogin = strings.TrimSpace(g.TgToken), strings.TrimSpace(g.TgChat), g.TgNoLogin
	if g.TgCpuAlert >= 0 && g.TgCpuAlert <= 100 {
		cur.TgCpuAlert, cur.TgCpuTouched = g.TgCpuAlert, true
	}
	if g.TgBackupHours >= 0 && g.TgBackupHours <= 720 {
		cur.TgBackupHours = g.TgBackupHours
	}
	cur.BasePath, cur.TLSCert, cur.TLSKey = bp, strings.TrimSpace(g.TLSCert), strings.TrimSpace(g.TLSKey)
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "saved; base path and TLS changes apply after a panel restart", nil)
}

func (a *API) uiPassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Old, New string }
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.New) < 8 {
		fail(w, "new password must be at least 8 characters")
		return
	}
	a.st.mu.RLock()
	cur := a.st.st.Admin.User
	a.st.mu.RUnlock()
	if !a.st.CheckAdmin(cur, req.Old) {
		fail(w, "current password is wrong")
		return
	}
	user := strings.TrimSpace(req.User)
	if user == "" {
		user = cur
	}
	a.st.SetAdmin(user, req.New)
	ok(w, "password changed", nil)
}

func (a *API) uiCerts(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	a.st.mu.Lock()
	in := a.st.st.Inbounds[id]
	if in == nil {
		a.st.mu.Unlock()
		fail(w, "Inbound not found")
		return
	}
	cn := strings.TrimSpace(r.Form.Get("cn"))
	if cn == "" {
		cn = "vpn-lite"
	}
	cb, err := genCerts(cn)
	if err != nil {
		a.st.mu.Unlock()
		fail(w, err.Error())
		return
	}
	if in.Settings == nil {
		in.Settings = map[string]any{}
	}
	switch in.Protocol {
	case "openvpn":
		in.Settings["caCert"], in.Settings["caKey"] = cb.CaCert, cb.CaKey
		in.Settings["serverCert"], in.Settings["serverKey"] = cb.ServerCert, cb.ServerKey
		in.Settings["tlsCrypt"] = cb.TlsCrypt
	case "openconnect":
		in.Settings["certificate"], in.Settings["key"] = cb.ServerCert+"\n"+cb.CaCert, cb.ServerKey
	default:
		a.st.mu.Unlock()
		fail(w, "this protocol has no certificates")
		return
	}
	a.st.touch()
	a.st.mu.Unlock()
	a.d.ReloadInbound(id)
	ok(w, "certificates generated", nil)
}

func (a *API) uiBackup(w http.ResponseWriter, r *http.Request) {
	a.st.Flush()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vpn-lite-%s.json"`, time.Now().Format("20060102-1504")))
	b, _ := os.ReadFile(a.st.path)
	w.Write(b)
}

func (a *API) uiRestart(w http.ResponseWriter, r *http.Request) {
	ok(w, "restarting", nil)
	go func() { time.Sleep(300 * time.Millisecond); a.st.Flush(); os.Exit(0) }() // systemd restarts us; daemons keep running
}

// ---------------------------------------------------------------- system stats

type sysInfo struct {
	CPU    float64 `json:"cpu"`
	MemPct float64 `json:"mem"`
	Load   string  `json:"load"`
	Uptime int64   `json:"uptime"`
	Ver    string  `json:"version"`
	RxBps  int64   `json:"rxBps"`
	TxBps  int64   `json:"txBps"`
}

var (
	sysMu                   sync.Mutex
	lastIdle, lastTotal     uint64
	lastRx, lastTx, lastNet int64
	lastSys                 sysInfo
)

func readSys() sysInfo {
	sysMu.Lock()
	defer sysMu.Unlock()
	if time.Now().UnixMilli()-lastNet < 1500 {
		return lastSys
	}
	s := sysInfo{}
	if f, err := os.Open("/proc/stat"); err == nil {
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			fs := strings.Fields(sc.Text())
			var tot, idle uint64
			for i, v := range fs[1:] {
				n, _ := strconv.ParseUint(v, 10, 64)
				tot += n
				if i == 3 || i == 4 {
					idle += n
				}
			}
			if lastTotal > 0 && tot > lastTotal {
				s.CPU = 100 * (1 - float64(idle-lastIdle)/float64(tot-lastTotal))
			}
			lastIdle, lastTotal = idle, tot
		}
		f.Close()
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail float64
		for _, l := range strings.Split(string(b), "\n") {
			fs := strings.Fields(l)
			if len(fs) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(fs[1], 64)
			switch fs[0] {
			case "MemTotal:":
				total = v
			case "MemAvailable:":
				avail = v
			}
		}
		if total > 0 {
			s.MemPct = 100 * (1 - avail/total)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fs := strings.Fields(string(b))
		if len(fs) >= 3 {
			s.Load = strings.Join(fs[:3], " ")
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		v, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
		s.Uptime = int64(v)
		s.Ver = version
	}
	var rx, tx int64
	if b, err := os.ReadFile("/proc/net/dev"); err == nil {
		for _, l := range strings.Split(string(b), "\n")[2:] {
			i := strings.IndexByte(l, ':')
			if i < 0 {
				continue
			}
			name := strings.TrimSpace(l[:i])
			if name == "lo" || strings.HasPrefix(name, "vl") || strings.HasPrefix(name, "ppp") || strings.HasPrefix(name, "vc") ||
				strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") {
				continue
			}
			fs := strings.Fields(l[i+1:])
			if len(fs) >= 9 {
				r, _ := strconv.ParseInt(fs[0], 10, 64)
				t, _ := strconv.ParseInt(fs[8], 10, 64)
				rx, tx = rx+r, tx+t
			}
		}
	}
	now := time.Now().UnixMilli()
	if lastNet > 0 && now > lastNet {
		dt := float64(now-lastNet) / 1000
		s.RxBps, s.TxBps = int64(float64(rx-lastRx)/dt), int64(float64(tx-lastTx)/dt)
	}
	lastRx, lastTx, lastNet = rx, tx, now
	lastSys = s
	return s
}

// l2tpPSK returns the IPsec pre-shared key shown to customers (empty when IPsec is off or not L2TP).
func l2tpPSK(in *Inbound) string {
	if in.Protocol != "l2tp" || !boolSetting(in.Settings, "ipsecEnable", true) {
		return ""
	}
	return strings.TrimSpace(strSetting(in.Settings, "ipsecPsk", ""))
}

// uiRestore replaces accounts and services with the ones in an uploaded backup. The panel login,
// port, certificate and signing keys of THIS panel are kept, so you stay logged in and reachable.
func (a *API) uiRestore(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil || len(body) == 0 {
		fail(w, "empty upload")
		return
	}
	var in State
	if json.Unmarshal(body, &in) != nil || (in.Inbounds == nil && in.Accounts == nil) {
		fail(w, "this is not a vpn-lite backup file")
		return
	}
	a.st.Flush()
	if cur, err := os.ReadFile(a.st.path); err == nil {
		os.WriteFile(a.st.path+".pre-restore", cur, 0o600)
	}
	a.st.mu.Lock()
	old := make([]int, 0, len(a.st.st.Inbounds))
	for id := range a.st.st.Inbounds {
		old = append(old, id)
	}
	if in.Inbounds == nil {
		in.Inbounds = map[int]*Inbound{}
	}
	if in.Accounts == nil {
		in.Accounts = map[string]*Account{}
	}
	next := in.NextInbound
	for id := range in.Inbounds {
		if id >= next {
			next = id + 1
		}
	}
	a.st.st.Inbounds, a.st.st.Accounts, a.st.st.NextInbound = in.Inbounds, in.Accounts, next
	g := &a.st.st.Global
	g.LimitStrategy, g.EvictGraceSec, g.DefaultSingleProto = in.Global.LimitStrategy, in.Global.EvictGraceSec, in.Global.DefaultSingleProto
	if g.LimitStrategy == "" {
		g.LimitStrategy = "evict"
	}
	if g.EvictGraceSec == 0 {
		g.EvictGraceSec = 30
	}
	a.st.touch()
	ids := old
	for id := range in.Inbounds {
		ids = append(ids, id)
	}
	nIn, nAcc := len(in.Inbounds), len(in.Accounts)
	a.st.mu.Unlock()
	a.st.Flush()
	for _, id := range ids {
		a.d.ReloadInbound(id)
	}
	ok(w, fmt.Sprintf("restored %d services and %d accounts", nIn, nAcc), nil)
}

// uiImport pulls services and accounts straight from a running vpn-ui panel.
func (a *API) uiImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL, User, Pass string
		PortShift       int
		Enable          bool
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.URL == "" || req.User == "" || req.Pass == "" {
		fail(w, "address, username and password of the old panel are required")
		return
	}
	a.st.mu.RLock()
	before := map[int]bool{}
	for id := range a.st.st.Inbounds {
		before[id] = true
	}
	a.st.mu.RUnlock()
	nIn, nAcc, skipped, err := importFromPanel(a.st, req.URL, req.User, req.Pass, req.PortShift, req.Enable)
	if err != nil {
		fail(w, err.Error())
		return
	}
	a.st.Flush()
	a.st.mu.RLock()
	var added []int
	for id := range a.st.st.Inbounds {
		if !before[id] {
			added = append(added, id)
		}
	}
	a.st.mu.RUnlock()
	for _, id := range added {
		a.d.ReloadInbound(id)
	}
	msg := fmt.Sprintf("imported %d services and %d accounts", nIn, nAcc)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d clients skipped: no password/email)", skipped)
	}
	if !req.Enable {
		msg += ". Services were created DISABLED: enable them when you are ready."
	}
	ok(w, msg, nil)
}

func (a *API) uiBackupNow(w http.ResponseWriter, r *http.Request) {
	if err := a.st.SendBackup(); err != nil {
		fail(w, err.Error())
		return
	}
	ok(w, "backup sent to Telegram", nil)
}
