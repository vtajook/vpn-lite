package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case string:
		var n int64
		fmt.Sscan(x, &n)
		return n
	}
	return 0
}

func asStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

// stateFromVpnUiDB converts a vpn-ui backup (the SQLite .db file the old panel downloads)
// into a vpn-lite state: inbounds keep their IDs (the bot uses them), accounts keep their
// credentials, volume, expiry, enabled flag, traffic counters and memberships.
// Protocols vpn-lite does not serve (pptp, sstp...) are left out and counted.
func stateFromVpnUiDB(data []byte) (*State, int, error) {
	tabs, err := sqliteTables(data)
	if err != nil {
		return nil, 0, err
	}
	ti, ta, tm, tc := tabs["inbounds"], tabs["accounts"], tabs["account_inbounds"], tabs["client_traffics"]
	if ti == nil || ta == nil || tm == nil {
		return nil, 0, fmt.Errorf("this does not look like a vpn-ui backup (inbounds/accounts tables missing)")
	}
	st := &State{Version: 1, Inbounds: map[int]*Inbound{}, Accounts: map[string]*Account{}, NextInbound: 1}
	g := func(t *sqTable, row []any, c string) any {
		if i := t.col(c); i >= 0 {
			return row[i]
		}
		return nil
	}
	skipped := 0
	for _, r := range ti.Rows {
		proto := asStr(g(ti, r, "protocol"))
		if !protoOK[proto] {
			skipped++
			continue
		}
		set := map[string]any{}
		json.Unmarshal([]byte(asStr(g(ti, r, "settings"))), &set)
		if set == nil {
			set = map[string]any{}
		}
		if ep, ok := set["externalProxy"].([]any); ok && len(ep) > 0 { // the connection domain customers use
			if m, ok := ep[0].(map[string]any); ok {
				if d, _ := m["dest"].(string); d != "" {
					set["connDomain"] = d
				}
			}
		}
		for _, k := range []string{"clients", "ipRanges", "localIp", "externalProxy", "userLimit", "userLimitStrategy", "tlsUseFile",
			"caCertFile", "serverCertFile", "serverKeyFile", "tlsCryptFile", "certificateFile", "keyFile", "allowRaw", "friendlyName"} {
			delete(set, k)
		}
		id := int(asInt(g(ti, r, "id")))
		in := &Inbound{ID: id, Remark: asStr(g(ti, r, "remark")), Enable: asInt(g(ti, r, "enable")) != 0,
			Listen: asStr(g(ti, r, "listen")), Port: int(asInt(g(ti, r, "port"))), Protocol: proto, Settings: set,
			SortOrder: int(asInt(g(ti, r, "sort_order")))}
		st.Inbounds[id] = in
		if id >= st.NextInbound {
			st.NextInbound = id + 1
		}
	}
	traffic := map[string][]any{}
	if tc != nil {
		for _, r := range tc.Rows {
			traffic[strings.ToLower(asStr(g(tc, r, "email")))] = r
		}
	}
	byID := map[int64]*Account{}
	for _, r := range ta.Rows {
		email := strings.TrimSpace(asStr(g(ta, r, "email")))
		pass := asStr(g(ta, r, "password"))
		if email == "" || pass == "" {
			continue
		}
		user := strings.TrimSpace(asStr(g(ta, r, "vpn_username")))
		if user == "" {
			user = email
		}
		a := &Account{Email: email, Username: user, Password: pass, SubID: asStr(g(ta, r, "sub_id")),
			Enable: asInt(g(ta, r, "enable")) != 0, TotalGB: asInt(g(ta, r, "total_gb")), ExpiryTime: asInt(g(ta, r, "expiry_time")),
			LimitIP: int(asInt(g(ta, r, "limit_ip"))), TgID: asInt(g(ta, r, "tg_id")), Comment: asStr(g(ta, r, "comment")),
			Reset: int(asInt(g(ta, r, "reset"))), SpeedDown: int(asInt(g(ta, r, "speed_limit_down"))),
			SpeedUp: int(asInt(g(ta, r, "speed_limit_up"))), CreatedAt: asInt(g(ta, r, "created_at"))}
		if a.SubID == "" {
			a.SubID = newSubID()
		}
		if a.CreatedAt == 0 {
			a.CreatedAt = nowMs()
		}
		if x, ok := traffic[strings.ToLower(email)]; ok {
			a.Up, a.Down, a.AllTime = asInt(g(tc, x, "up")), asInt(g(tc, x, "down")), asInt(g(tc, x, "all_time"))
			a.LastOnline = asInt(g(tc, x, "last_online"))
		}
		st.Accounts[ekey(email)] = a
		byID[asInt(g(ta, r, "id"))] = a
	}
	for _, r := range tm.Rows {
		a := byID[asInt(g(tm, r, "account_id"))]
		in := st.Inbounds[int(asInt(g(tm, r, "inbound_id")))]
		if a == nil || in == nil {
			continue
		}
		clash := false
		for _, id := range a.Inbounds { // one inbound per protocol
			if st.Inbounds[id].Protocol == in.Protocol {
				clash = true
			}
		}
		if !clash && !hasInt(a.Inbounds, in.ID) {
			a.Inbounds = append(a.Inbounds, in.ID)
		}
	}
	for _, a := range st.Accounts {
		sort.Ints(a.Inbounds)
	}
	return st, skipped, nil
}
