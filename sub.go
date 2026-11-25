package main

// Public subscription page: /sub/<subId> shows one account's login, quota, expiry and the
// connection details of every service it is on, plus .ovpn downloads. The random subId is the
// only credential; it is created with the account and never listed anywhere public.
// ?format=json returns the same data for apps and bots.

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type subSvc struct {
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
	Remark   string `json:"remark"`
	Server   string `json:"server"`
	Port     int    `json:"port,omitempty"`
	PSK      string `json:"psk,omitempty"`
	Ovpn     bool   `json:"-"`
	UDP      string `json:"ovpnUdp,omitempty"`
	TCP      string `json:"ovpnTcp,omitempty"`
	Both     string `json:"ovpnBoth,omitempty"`
}

type subView struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Status   string   `json:"status"`
	Expiry   int64    `json:"expiry"`
	DaysLeft int      `json:"daysLeft"`
	Used     int64    `json:"used"`
	Total    int64    `json:"total"`
	Devices  int      `json:"devices"`
	Services []subSvc `json:"services"`
}

// subMiss limits wrong-id guesses per IP (20 per minute).
var subMiss = struct {
	sync.Mutex
	m map[string][]int64
}{m: map[string][]int64{}}

func subLimited(ip string, add bool) bool {
	subMiss.Lock()
	defer subMiss.Unlock()
	now := time.Now().UnixMilli()
	keep := subMiss.m[ip][:0]
	for _, t := range subMiss.m[ip] {
		if now-t < 60000 {
			keep = append(keep, t)
		}
	}
	if add {
		keep = append(keep, now)
	}
	if len(keep) == 0 {
		delete(subMiss.m, ip)
	} else {
		subMiss.m[ip] = keep
	}
	if len(subMiss.m) > 5000 { // never let a scan grow the table without bound
		subMiss.m = map[string][]int64{}
	}
	return len(keep) > 20
}

// subHost is the address a client should connect to for an inbound.
func subHost(in *Inbound, reqHost string) string {
	if arr, ok := in.Settings["externalProxy"].([]any); ok {
		for _, e := range arr {
			if m, _ := e.(map[string]any); m != nil {
				if d := strings.TrimSpace(strSetting(m, "dest", "")); d != "" {
					return d
				}
			}
		}
	}
	if h := strings.TrimSpace(strSetting(in.Settings, "connDomain", "")); h != "" {
		return h
	}
	if h := strings.TrimSpace(in.Listen); h != "" && h != "0.0.0.0" {
		return h
	}
	if hh, _, err := net.SplitHostPort(reqHost); err == nil {
		return hh
	}
	return reqHost
}

// subLookup finds the account that owns subID and builds its view. ok is false for an unknown id.
func (a *API) subLookup(subID, reqHost string) (v subView, acc *Account, ok bool) {
	if len(subID) < 8 {
		return v, nil, false
	}
	now := nowMs()
	a.st.mu.RLock()
	defer a.st.mu.RUnlock()
	for _, x := range a.st.st.Accounts {
		if x.SubID == "" || subtle.ConstantTimeCompare([]byte(x.SubID), []byte(subID)) != 1 {
			continue
		}
		acc = x
		break
	}
	if acc == nil {
		return v, nil, false
	}
	limit := acc.LimitIP
	if limit <= 0 {
		limit = a.st.st.Global.DefaultLimit
		if limit < 1 {
			limit = 1
		}
	}
	v = subView{Username: acc.Username, Password: acc.Password, Status: statusOf(acc, now), Expiry: acc.ExpiryTime,
		Used: acc.Up + acc.Down, Total: acc.TotalGB, Devices: limit}
	if acc.ExpiryTime > 0 {
		v.DaysLeft = int((acc.ExpiryTime - now + 86399999) / 86400000)
		if acc.ExpiryTime <= now {
			v.DaysLeft = 0
		}
	}
	ids := append([]int(nil), acc.Inbounds...)
	sort.Ints(ids)
	for _, id := range ids {
		in := a.st.st.Inbounds[id]
		if in == nil || !in.Enable {
			continue
		}
		s := subSvc{ID: id, Protocol: in.Protocol, Remark: in.Remark, Server: subHost(in, reqHost), Port: in.Port}
		switch in.Protocol {
		case "l2tp":
			s.PSK = l2tpPSK(in)
		case "openvpn":
			s.Ovpn = true
			s.Port = 0
			base := fmt.Sprintf("sub/%s/ovpn/%d/", subID, id)
			s.UDP, s.TCP, s.Both = base+"udp", base+"tcp", base+"both"
		}
		v.Services = append(v.Services, s)
	}
	return v, acc, true
}

func subHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
}

func (a *API) subPage(w http.ResponseWriter, r *http.Request) {
	subHeaders(w)
	ip := clientIP(r)
	if subLimited(ip, false) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	v, _, ok := a.subLookup(r.PathValue("sid"), r.Host)
	if !ok {
		subLimited(ip, true)
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, v)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := subTpl.Execute(w, v); err != nil {
		Events.Add("error", "sub", v.Username, "render: %v", err)
	}
}

func (a *API) subOvpn(w http.ResponseWriter, r *http.Request) {
	subHeaders(w)
	ip := clientIP(r)
	if subLimited(ip, false) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	sid := r.PathValue("sid")
	id := pathID(r)
	proto := r.PathValue("proto")
	_, acc, ok := a.subLookup(sid, r.Host)
	if !ok {
		subLimited(ip, true)
		http.NotFound(w, r)
		return
	}
	a.st.ensureOvpnCerts(id) // an inbound that was never started has no certificates yet
	a.st.mu.RLock()
	in := a.st.st.Inbounds[id]
	user, pass := acc.Username, acc.Password
	member := in != nil && in.Enable && in.Protocol == "openvpn" && hasInt(acc.Inbounds, id)
	a.st.mu.RUnlock()
	if !member {
		http.NotFound(w, r)
		return
	}
	cfg, err := ovpnClientConfig(in, proto, r.Host, user, pass)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := safeName(user, id)
	if proto != "both" && proto != "all" {
		name += "-" + proto
	}
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.ovpn"`, name))
	w.Write([]byte(cfg))
}

var subTpl = template.Must(template.New("sub").Funcs(template.FuncMap{
	"gb": func(b int64) string {
		return fmt.Sprintf("%.2f", float64(b)/1073741824)
	},
	"pct": func(u, t int64) int {
		if t <= 0 {
			return 0
		}
		p := int(float64(u) * 100 / float64(t))
		if p > 100 {
			p = 100
		}
		return p
	},
	"iso": func(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05Z") },
	"proto": func(p string) string {
		switch p {
		case "openvpn":
			return "OpenVPN"
		case "l2tp":
			return "L2TP/IPsec"
		case "openconnect":
			return "Cisco AnyConnect (OpenConnect)"
		}
		return p
	},
	"fa": func(s string) string {
		switch s {
		case "active":
			return "فعال"
		case "expired":
			return "منقضی‌شده"
		case "depleted":
			return "حجم تمام شده"
		}
		return "غیرفعال"
	},
}).Parse(`<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>اطلاعات اشتراک</title>
<style>
:root{--bg:#f4f6fa;--card:#fff;--tx:#1a2233;--mu:#68738a;--bd:#e1e6ef;--ac:#2563eb;--ok:#16a34a;--bad:#dc2626;--warn:#d97706}
@media(prefers-color-scheme:dark){:root{--bg:#0e131c;--card:#171e2b;--tx:#e8edf6;--mu:#94a0b6;--bd:#273146;--ac:#5b8cff;--ok:#34d399;--bad:#f87171;--warn:#fbbf24}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.7 system-ui,"Vazirmatn",Tahoma,sans-serif}
.w{max-width:520px;margin:0 auto;padding:16px}
.c{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px;margin-bottom:14px}
h1{font-size:18px;margin:4px 0 12px}h2{font-size:15px;margin:0 0 10px}
.st{display:inline-block;padding:2px 12px;border-radius:99px;font-size:13px;color:#fff}
.st.active{background:var(--ok)}.st.expired,.st.depleted{background:var(--bad)}.st.disabled{background:var(--mu)}
.r{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:7px 0;border-bottom:1px dashed var(--bd)}
.r:last-child{border:0}.k{color:var(--mu);font-size:13px;white-space:nowrap}
.v{direction:ltr;text-align:left;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;flex:1}
.v.t{direction:rtl;text-align:right;font-family:inherit}
button,.b{font:inherit;font-size:13px;border:1px solid var(--bd);background:var(--bg);color:var(--tx);border-radius:8px;padding:3px 10px;cursor:pointer;text-decoration:none;display:inline-block}
.b.p{background:var(--ac);border-color:var(--ac);color:#fff}
.bar{height:8px;background:var(--bd);border-radius:9px;overflow:hidden;margin:4px 0 2px}.bar i{display:block;height:100%;background:var(--ac)}
.dl{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.ft{text-align:center;color:var(--mu);font-size:12px;margin-top:8px}
</style></head><body><div class="w">
<div class="c"><h1>اطلاعات اشتراک شما</h1>
<div class="r"><span class="k">وضعیت</span><span class="st {{.Status}}">{{fa .Status}}</span></div>
<div class="r"><span class="k">نام کاربری</span><span class="v">{{.Username}}</span><button data-c="{{.Username}}">کپی</button></div>
<div class="r"><span class="k">رمز عبور</span><span class="v">{{.Password}}</span><button data-c="{{.Password}}">کپی</button></div>
<div class="r"><span class="k">تعداد دستگاه همزمان</span><span class="v t">{{.Devices}}</span></div>
<div class="r"><span class="k">انقضا</span><span class="v t">{{if .Expiry}}<span data-d="{{iso .Expiry}}">{{iso .Expiry}}</span>{{if gt .DaysLeft 0}} ({{.DaysLeft}} روز مانده){{end}}{{else}}نامحدود{{end}}</span></div>
<div style="padding-top:8px"><div class="r" style="border:0;padding:0"><span class="k">حجم مصرفی</span><span class="v t">{{gb .Used}} گیگ از {{if .Total}}{{gb .Total}} گیگ{{else}}نامحدود{{end}}</span></div>
{{if .Total}}<div class="bar"><i style="width:{{pct .Used .Total}}%"></i></div>{{end}}</div></div>
{{range .Services}}<div class="c"><h2>{{proto .Protocol}}{{if .Remark}} <span class="k">· {{.Remark}}</span>{{end}}</h2>
<div class="r"><span class="k">آدرس سرور</span><span class="v">{{.Server}}</span><button data-c="{{.Server}}">کپی</button></div>
{{if .Port}}<div class="r"><span class="k">پورت</span><span class="v">{{.Port}}</span></div>{{end}}
{{if .PSK}}<div class="r"><span class="k">کلید IPsec (PSK)</span><span class="v">{{.PSK}}</span><button data-c="{{.PSK}}">کپی</button></div>{{end}}
{{if .Ovpn}}<div class="dl"><a class="b p" href="{{.Both}}">دانلود فایل ovpn (UDP و TCP)</a><a class="b" href="{{.UDP}}">فقط UDP</a><a class="b" href="{{.TCP}}">فقط TCP</a></div>{{end}}
</div>{{end}}
<div class="ft">این لینک مخصوص شماست؛ آن را با کسی به اشتراک نگذارید.</div>
</div>
<script>
document.querySelectorAll("[data-c]").forEach(function(b){b.onclick=function(){var t=b.getAttribute("data-c"),o=b.textContent;
function ok(){b.textContent="کپی شد";setTimeout(function(){b.textContent=o},1200)}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok)}else{var x=document.createElement("textarea");x.value=t;document.body.appendChild(x);x.select();try{document.execCommand("copy");ok()}catch(e){}x.remove()}}});
document.querySelectorAll("[data-d]").forEach(function(e){try{e.textContent=new Date(e.getAttribute("data-d")).toLocaleString("fa-IR-u-ca-persian",{year:"numeric",month:"long",day:"numeric",hour:"2-digit",minute:"2-digit"})}catch(x){}});
</script></body></html>`))
