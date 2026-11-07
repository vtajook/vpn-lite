package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Daemons is what the API needs from the protocol engines.
type Daemons interface {
	ReloadInbound(id int)     // inbound added/changed/removed: (re)start or stop its daemon
	Kick(email string)        // drop every live session of the account right now
	Online() map[string]int64 // email -> last seen ms for accounts with a live session
}

type API struct {
	st   *Store
	d    Daemons
	base string // "/" or "/xyz/"
}

type envelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Obj     any    `json:"obj"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
func ok(w http.ResponseWriter, msg string, obj any) { writeJSON(w, envelope{true, msg, obj}) }
func fail(w http.ResponseWriter, msg string)        { writeJSON(w, envelope{false, msg, nil}) }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	p := "/panel/api/inbounds"
	g := func(path string, h http.HandlerFunc) { mux.HandleFunc("GET "+p+path, a.api(h)) }
	po := func(path string, h http.HandlerFunc) { mux.HandleFunc("POST "+p+path, a.api(h)) }

	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("GET /logout", a.logout)
	mux.HandleFunc("GET /{$}", a.page)

	g("/list", a.list)
	g("/get/{id}", a.get)
	g("/getClientTraffics/{email}", a.clientTraffic)
	g("/getClientTrafficsById/{id}", a.clientTraffic)
	g("/resellerBalance", func(w http.ResponseWriter, r *http.Request) { fail(w, "not a reseller") })
	g("/{id}/ovpn/{proto}", a.ovpnFile)
	g("/pools", a.pools)

	po("/add", a.addInbound)
	po("/update/{id}", a.updateInbound)
	po("/del/{id}", a.delInbound)
	po("/addClient", a.addClient)
	po("/updateClient/{clientId}", a.updateClient)
	po("/{id}/delClient/{clientId}", a.delClient)
	po("/{id}/delClientByEmail/{email}", a.delClient)
	po("/{id}/resetClientTraffic/{email}", a.resetTraffic)
	po("/resetAllClientTraffics/{id}", a.resetAll)
	po("/resetAllTraffics", a.resetAll)
	po("/delDepletedClients/{id}", a.delDepleted)
	po("/updateClientTraffic/{email}", a.setTraffic)
	po("/clientIps/{email}", a.clientIps)
	po("/clearClientIps/{email}", func(w http.ResponseWriter, r *http.Request) { ok(w, "", nil) })
	po("/onlines", a.onlines)
	po("/lastOnline", a.lastOnline)

	a.uiRoutes(mux)

	var h http.Handler = mux
	if a.base != "/" && a.base != "" {
		h = http.StripPrefix(strings.TrimSuffix(a.base, "/"), mux)
	}
	return gzipMW(h)
}

// api guards a handler: no cookie => bare 404 (hides the endpoints, like the old panel).
func (a *API) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.st.loggedIn(r) {
			http.NotFound(w, r)
			return
		}
		r.ParseForm()
		h(w, r)
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.RemoteAddr
	if i := strings.LastIndexByte(ip, ':'); i > 0 {
		ip = ip[:i]
	}
	if !loginAllowed(ip) {
		fail(w, "Too many failed attempts; try again in a few minutes")
		return
	}
	if !a.st.CheckAdmin(r.PostFormValue("username"), r.PostFormValue("password")) {
		loginFailed(ip)
		Events.Add("login-fail", "panel", r.PostFormValue("username"), "from %s", ip)
		a.st.NotifyLogin(false, r.PostFormValue("username"), ip)
		fail(w, "Wrong username or password")
		return
	}
	a.st.issue(w, r.TLS != nil)
	a.st.NotifyLogin(true, r.PostFormValue("username"), ip)
	ok(w, "Login successful", nil)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: a.base, MaxAge: -1})
	http.Redirect(w, r, a.base, http.StatusFound)
}

func pathID(r *http.Request) int { n, _ := strconv.Atoi(r.PathValue("id")); return n }

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	light := r.URL.Query().Get("light") == "1"
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	out := []inboundJSON{}
	for _, in := range a.st.sortedInbounds() {
		out = append(out, a.st.projectInboundLocked(in, !light))
	}
	ok(w, "", out)
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	in := a.st.st.Inbounds[pathID(r)]
	if in == nil {
		fail(w, "Inbound not found")
		return
	}
	ok(w, "", a.st.projectInboundLocked(in, true))
}

func (a *API) clientTraffic(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	var acc *Account
	if e := r.PathValue("email"); e != "" {
		acc = a.st.st.Accounts[ekey(e)]
	} else if id := r.PathValue("id"); id != "" {
		acc = a.st.accountByIdentityLocked(0, id)
	}
	if acc == nil {
		fail(w, "Client not found")
		return
	}
	ok(w, "", acc.traffic())
}

// ---------------------------------------------------------------- inbounds

var protoOK = map[string]bool{"openvpn": true, "l2tp": true, "openconnect": true}

func (a *API) fillInbound(r *http.Request, in *Inbound, isNew bool) string {
	f := r.Form
	has := func(k string) bool { _, ok := f[k]; return ok }
	if has("remark") {
		in.Remark = f.Get("remark")
	}
	if has("enable") {
		in.Enable = f.Get("enable") == "true"
	} else if isNew {
		in.Enable = true
	}
	if has("listen") {
		in.Listen = f.Get("listen")
	}
	if has("port") {
		n, err := strconv.Atoi(f.Get("port"))
		if err != nil || n < 1 || n > 65535 {
			return "Invalid port (must be 1-65535): " + f.Get("port")
		}
		in.Port = n
	}
	if has("protocol") {
		in.Protocol = strings.ToLower(f.Get("protocol"))
	}
	if !protoOK[in.Protocol] {
		return "Unsupported protocol: " + in.Protocol
	}
	if has("total") {
		in.Total, _ = strconv.ParseInt(f.Get("total"), 10, 64)
	}
	if has("expiryTime") {
		in.ExpiryTime, _ = strconv.ParseInt(f.Get("expiryTime"), 10, 64)
	}
	if has("settings") {
		m := map[string]any{}
		if err := json.Unmarshal([]byte(f.Get("settings")), &m); err != nil {
			return "settings is not valid JSON"
		}
		delete(m, "clients")
		in.Settings = m
	}
	if in.Settings == nil {
		in.Settings = map[string]any{}
	}
	if in.Protocol == "l2tp" && in.Port == 1701 && boolSetting(in.Settings, "ipsecEnable", true) &&
		strings.TrimSpace(strSetting(in.Settings, "ipsecPsk", "")) == "" {
		return "IPsec pre-shared key is required (or set ipsecEnable to false)"
	}
	return ""
}

func (a *API) addInbound(w http.ResponseWriter, r *http.Request) {
	in := &Inbound{}
	if msg := a.fillInbound(r, in, true); msg != "" {
		fail(w, msg)
		return
	}
	a.st.mu.Lock()
	if msg := a.st.portClashLocked(in); msg != "" {
		a.st.mu.Unlock()
		fail(w, msg)
		return
	}
	in.ID = a.st.st.NextInbound
	a.st.st.NextInbound++
	in.SortOrder = in.ID
	a.st.st.Inbounds[in.ID] = in
	a.st.touch()
	v := a.st.projectInboundLocked(in, true)
	a.st.mu.Unlock()
	a.d.ReloadInbound(in.ID)
	ok(w, "Inbound created successfully", v)
}

func (a *API) updateInbound(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	a.st.mu.Lock()
	in := a.st.st.Inbounds[id]
	if in == nil {
		a.st.mu.Unlock()
		fail(w, "Inbound not found")
		return
	}
	cp := *in // partial update: bind onto the stored row
	if msg := a.fillInbound(r, &cp, false); msg != "" {
		a.st.mu.Unlock()
		fail(w, msg)
		return
	}
	cp.ID = id
	if msg := a.st.portClashLocked(&cp); msg != "" {
		a.st.mu.Unlock()
		fail(w, msg)
		return
	}
	*in = cp
	in.ID = id
	a.st.touch()
	v := a.st.projectInboundLocked(in, true)
	a.st.mu.Unlock()
	a.d.ReloadInbound(id)
	ok(w, "Inbound updated successfully", v)
}

func (a *API) delInbound(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	a.st.mu.Lock()
	if a.st.st.Inbounds[id] == nil {
		a.st.mu.Unlock()
		fail(w, "Inbound not found")
		return
	}
	delete(a.st.st.Inbounds, id)
	var orphans []string
	for k, acc := range a.st.st.Accounts {
		if hasInt(acc.Inbounds, id) {
			acc.Inbounds = delInt(acc.Inbounds, id)
			if len(acc.Inbounds) == 0 {
				orphans = append(orphans, acc.Email)
				delete(a.st.st.Accounts, k)
			}
		}
	}
	a.st.touch()
	a.st.mu.Unlock()
	for _, e := range orphans {
		a.d.Kick(e)
	}
	a.d.ReloadInbound(id)
	ok(w, "Inbound deleted successfully", id)
}

func (a *API) pools(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	out := map[string]any{}
	for _, in := range a.st.sortedInbounds() {
		out[itoa(in.ID)] = map[string]any{"members": len(a.st.membersLocked(in.ID))}
	}
	ok(w, "", out)
}

// ---------------------------------------------------------------- accounts

func parseClient(r *http.Request, base clientJSON) (clientJSON, string) {
	var wrap struct {
		Clients []json.RawMessage `json:"clients"`
	}
	if err := json.Unmarshal([]byte(r.Form.Get("settings")), &wrap); err != nil || len(wrap.Clients) != 1 {
		return base, "settings.clients must hold exactly one client"
	}
	c := base
	if err := json.Unmarshal(wrap.Clients[0], &c); err != nil {
		return base, "invalid client JSON: " + err.Error()
	}
	return c, ""
}

// membership reads the repeated inboundIds keys plus the target id.
func membership(r *http.Request, target int) (ids []int, present bool) {
	vals, present := r.Form["inboundIds"]
	seen := map[int]bool{}
	add := func(n int) {
		if n > 0 && !seen[n] {
			seen[n] = true
			ids = append(ids, n)
		}
	}
	add(target)
	for _, v := range vals {
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		add(n)
	}
	return
}

func (a *API) addClient(w http.ResponseWriter, r *http.Request) {
	target, _ := strconv.Atoi(r.Form.Get("id"))
	c, msg := parseClient(r, clientJSON{Enable: true})
	if msg != "" {
		fail(w, msg)
		return
	}
	email := strings.TrimSpace(c.Email)
	if email == "" {
		fail(w, "client email is empty")
		return
	}
	user := strings.TrimSpace(c.ID)
	if user == "" {
		user = email
	}
	if c.Password == "" {
		fail(w, "client password is empty")
		return
	}
	ids, _ := membership(r, target)
	a.st.mu.Lock()
	for _, id := range ids {
		if a.st.st.Inbounds[id] == nil {
			a.st.mu.Unlock()
			fail(w, "Inbound not found: "+itoa(id))
			return
		}
	}
	if a.st.st.Accounts[ekey(email)] != nil {
		a.st.mu.Unlock()
		fail(w, "Duplicate email: "+email)
		return
	}
	for _, o := range a.st.st.Accounts {
		if strings.EqualFold(o.Username, user) {
			a.st.mu.Unlock()
			fail(w, "Duplicate username: "+user)
			return
		}
	}
	if msg := a.st.checkSameProtoLocked(ids); msg != "" {
		a.st.mu.Unlock()
		fail(w, msg)
		return
	}
	if c.SubID == "" {
		c.SubID = newSubID()
	}
	single := c.SingleProto
	if !strings.Contains(r.Form.Get("settings"), `"singleProto"`) {
		single = a.st.st.Global.DefaultSingleProto // the bot does not send it: use the panel default
	}
	acc := &Account{Email: email, Username: user, Password: c.Password, SubID: c.SubID, Enable: c.Enable,
		TotalGB: c.TotalGB, ExpiryTime: c.ExpiryTime, LimitIP: c.LimitIP, TgID: c.TgID, Comment: c.Comment,
		Reset: c.Reset, SpeedDown: c.SpeedDown, SpeedUp: c.SpeedUp, SingleProto: single, Inbounds: ids, CreatedAt: nowMs()}
	a.st.st.Accounts[ekey(email)] = acc
	a.st.touch()
	a.st.mu.Unlock()
	for _, id := range ids {
		a.d.ReloadInbound(id)
	}
	ok(w, "Client added successfully", nil)
}

// checkSameProtoLocked: one account may be on at most one inbound per protocol,
// because the daemons key credentials per protocol and would otherwise pick arbitrarily.
func (s *Store) checkSameProtoLocked(ids []int) string {
	seen := map[string]int{}
	for _, id := range ids {
		in := s.st.Inbounds[id]
		if in == nil {
			continue
		}
		if o, dup := seen[in.Protocol]; dup {
			return "an account cannot be on two " + in.Protocol + " inbounds at once (" + itoa(o) + ", " + itoa(id) + ")"
		}
		seen[in.Protocol] = id
	}
	return ""
}

func (a *API) updateClient(w http.ResponseWriter, r *http.Request) {
	target, _ := strconv.Atoi(r.Form.Get("id"))
	ident := r.PathValue("clientId")
	a.st.mu.Lock()
	acc := a.st.accountByIdentityLocked(target, ident)
	if _, present := r.Form["inboundIds"]; acc == nil && present {
		// the panel UI lists a newly ticked inbound first; the account is not a member yet
		acc = a.st.accountByIdentityLocked(0, ident)
	}
	if acc == nil {
		a.st.mu.Unlock()
		fail(w, "Client not found")
		return
	}
	c, msg := parseClient(r, acc.client())
	if msg != "" {
		a.st.mu.Unlock()
		fail(w, msg)
		return
	}
	if c.Password == "" {
		a.st.mu.Unlock()
		fail(w, "client password is empty")
		return
	}
	newUser := strings.TrimSpace(c.ID)
	if newUser == "" {
		newUser = acc.Username
	}
	if !strings.EqualFold(newUser, acc.Username) {
		for _, o := range a.st.st.Accounts {
			if o != acc && strings.EqualFold(o.Username, newUser) {
				a.st.mu.Unlock()
				fail(w, "Duplicate username: "+newUser)
				return
			}
		}
	}
	oldIDs := append([]int(nil), acc.Inbounds...)
	newIDs := oldIDs
	if _, present := r.Form["inboundIds"]; present {
		newIDs, _ = membership(r, target)
		for _, id := range newIDs {
			if a.st.st.Inbounds[id] == nil {
				a.st.mu.Unlock()
				fail(w, "Inbound not found: "+itoa(id))
				return
			}
		}
		if msg := a.st.checkSameProtoLocked(newIDs); msg != "" {
			a.st.mu.Unlock()
			fail(w, msg)
			return
		}
	}
	credChanged := acc.Password != c.Password || !strings.EqualFold(acc.Username, newUser) || !c.Enable
	acc.Username, acc.Password, acc.Enable = newUser, c.Password, c.Enable
	acc.TotalGB, acc.ExpiryTime, acc.LimitIP = c.TotalGB, c.ExpiryTime, c.LimitIP
	acc.TgID, acc.Comment, acc.Reset = c.TgID, c.Comment, c.Reset
	speedChanged := acc.SpeedDown != c.SpeedDown || acc.SpeedUp != c.SpeedUp
	acc.SpeedDown, acc.SpeedUp = c.SpeedDown, c.SpeedUp
	acc.SingleProto = c.SingleProto
	if c.SubID != "" {
		acc.SubID = c.SubID
	}
	if ne := strings.TrimSpace(c.Email); ne != "" && !strings.EqualFold(ne, acc.Email) {
		if a.st.st.Accounts[ekey(ne)] != nil {
			a.st.mu.Unlock()
			fail(w, "Duplicate email: "+ne)
			return
		}
		delete(a.st.st.Accounts, ekey(acc.Email))
		a.d.Kick(acc.Email)
		acc.Email = ne
		a.st.st.Accounts[ekey(ne)] = acc
	}
	acc.Inbounds = newIDs
	a.st.touch()
	email := acc.Email
	dead := !acc.Enable || acc.expired(nowMs()) || acc.overQuota()
	a.st.mu.Unlock()
	if speedChanged {
		Shaper.Refresh(email)
	}
	if credChanged || dead {
		a.d.Kick(email)
	}
	for _, id := range unionInts(oldIDs, newIDs) {
		a.d.ReloadInbound(id)
	}
	ok(w, "Client updated successfully", nil)
}

func unionInts(a, b []int) []int {
	m := map[int]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		m[x] = true
	}
	out := make([]int, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Ints(out)
	return out
}

// delClient serves both delClient/{clientId} and delClientByEmail/{email}.
func (a *API) delClient(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	ident := r.PathValue("clientId")
	if ident == "" {
		ident = r.PathValue("email")
	}
	a.st.mu.Lock()
	acc := a.st.accountByIdentityLocked(id, ident)
	if acc == nil {
		a.st.mu.Unlock()
		fail(w, "Client not found")
		return
	}
	acc.Inbounds = delInt(acc.Inbounds, id)
	email := acc.Email
	if len(acc.Inbounds) == 0 {
		delete(a.st.st.Accounts, ekey(email))
	}
	a.st.touch()
	a.st.mu.Unlock()
	a.d.Kick(email)
	a.d.ReloadInbound(id)
	ok(w, "Client deleted successfully", nil)
}

func (a *API) resetTraffic(w http.ResponseWriter, r *http.Request) {
	a.st.mu.Lock()
	acc := a.st.st.Accounts[ekey(r.PathValue("email"))]
	if acc == nil {
		a.st.mu.Unlock()
		fail(w, "Client not found")
		return
	}
	acc.Up, acc.Down = 0, 0
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "Traffic reset successfully", nil)
}

func (a *API) resetAll(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	a.st.mu.Lock()
	for _, acc := range a.st.st.Accounts {
		if id == 0 || hasInt(acc.Inbounds, id) {
			acc.Up, acc.Down = 0, 0
		}
	}
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "Traffic reset successfully", nil)
}

func (a *API) delDepleted(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	now := nowMs()
	var gone []string
	a.st.mu.Lock()
	for k, acc := range a.st.st.Accounts {
		if (id == 0 || hasInt(acc.Inbounds, id)) && (acc.expired(now) || acc.overQuota()) {
			gone = append(gone, acc.Email)
			delete(a.st.st.Accounts, k)
		}
	}
	a.st.touch()
	a.st.mu.Unlock()
	for _, e := range gone {
		a.d.Kick(e)
	}
	ok(w, "Depleted clients deleted", len(gone))
}

func (a *API) setTraffic(w http.ResponseWriter, r *http.Request) {
	a.st.mu.Lock()
	acc := a.st.st.Accounts[ekey(r.PathValue("email"))]
	if acc == nil {
		a.st.mu.Unlock()
		fail(w, "Client not found")
		return
	}
	acc.Up, _ = strconv.ParseInt(r.Form.Get("upload"), 10, 64)
	acc.Down, _ = strconv.ParseInt(r.Form.Get("download"), 10, 64)
	a.st.touch()
	a.st.mu.Unlock()
	ok(w, "Traffic updated", nil)
}

func (a *API) clientIps(w http.ResponseWriter, r *http.Request) {
	ips := Sessions.IPsOf(r.PathValue("email"))
	if len(ips) == 0 {
		ok(w, "", "No IP Record")
		return
	}
	ok(w, "", ips)
}

func (a *API) onlines(w http.ResponseWriter, r *http.Request) {
	on := a.d.Online()
	out := make([]string, 0, len(on))
	for e := range on {
		out = append(out, e)
	}
	sort.Strings(out)
	ok(w, "", out)
}

func (a *API) lastOnline(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	out := map[string]int64{}
	for _, acc := range a.st.st.Accounts {
		if acc.LastOnline > 0 {
			out[acc.Email] = acc.LastOnline
		}
	}
	ok(w, "", out)
}

func jsonDecode(resp *http.Response, v any) { json.NewDecoder(resp.Body).Decode(v) }

// portsOf lists the transport/port pairs an inbound listens on, e.g. "udp/1194".
func portsOf(in *Inbound) []string {
	p := itoa(in.Port)
	switch in.Protocol {
	case "openvpn":
		var out []string
		if boolSetting(in.Settings, "udpEnable", true) {
			out = append(out, "udp/"+p)
		}
		if boolSetting(in.Settings, "tcpEnable", true) {
			out = append(out, "tcp/"+itoa(tcpPort(in)))
		}
		return out
	case "openconnect":
		return []string{"tcp/" + p, "udp/" + p}
	case "l2tp":
		out := []string{"udp/" + p}
		if p == "1701" && boolSetting(in.Settings, "ipsecEnable", true) {
			out = append(out, "udp/500", "udp/4500")
		}
		return out
	}
	return nil
}

// portClashLocked reports a listen-port conflict between enabled inbounds (same transport, same port).
func (s *Store) portClashLocked(in *Inbound) string {
	if !in.Enable {
		return ""
	}
	mine := portsOf(in)
	for _, o := range s.st.Inbounds {
		if o.ID == in.ID || !o.Enable {
			continue
		}
		for _, x := range portsOf(o) {
			for _, y := range mine {
				if x == y {
					return "Port " + y + " is already used by inbound " + itoa(o.ID) + " (" + o.Remark + ")"
				}
			}
		}
	}
	return ""
}
