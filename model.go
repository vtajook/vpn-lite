package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type clientJSON struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Enable      bool   `json:"enable"`
	LimitIP     int    `json:"limitIp"`
	TotalGB     int64  `json:"totalGB"`
	ExpiryTime  int64  `json:"expiryTime"`
	TgID        int64  `json:"tgId"`
	SubID       string `json:"subId"`
	Comment     string `json:"comment"`
	Reset       int    `json:"reset"`
	Password    string `json:"password"`
	SpeedDown   int    `json:"speedLimitDown"`
	SpeedUp     int    `json:"speedLimitUp"`
	SingleProto bool   `json:"singleProto"`
}

type trafficJSON struct {
	ID         int    `json:"id"`
	InboundID  int    `json:"inboundId"`
	Enable     bool   `json:"enable"`
	Email      string `json:"email"`
	UUID       string `json:"uuid"`
	SubID      string `json:"subId"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	AllTime    int64  `json:"allTime"`
	Total      int64  `json:"total"`
	ExpiryTime int64  `json:"expiryTime"`
	Reset      int    `json:"reset"`
	LastOnline int64  `json:"lastOnline"`
}

type inboundJSON struct {
	ID             int           `json:"id"`
	Up             int64         `json:"up"`
	Down           int64         `json:"down"`
	Total          int64         `json:"total"`
	Remark         string        `json:"remark"`
	Enable         bool          `json:"enable"`
	ExpiryTime     int64         `json:"expiryTime"`
	ClientStats    []trafficJSON `json:"clientStats"`
	Listen         string        `json:"listen"`
	Port           int           `json:"port"`
	Protocol       string        `json:"protocol"`
	Settings       string        `json:"settings"`
	StreamSettings string        `json:"streamSettings"`
	Tag            string        `json:"tag"`
	Sniffing       string        `json:"sniffing"`
	SortOrder      int           `json:"sortOrder"`
}

func (a *Account) client() clientJSON {
	return clientJSON{ID: a.Username, Email: a.Email, Enable: a.Enable, LimitIP: a.LimitIP,
		TotalGB: a.TotalGB, ExpiryTime: a.ExpiryTime, TgID: a.TgID, SubID: a.SubID,
		Comment: a.Comment, Reset: a.Reset, Password: a.Password,
		SpeedDown: a.SpeedDown, SpeedUp: a.SpeedUp, SingleProto: a.SingleProto}
}

func (a *Account) traffic() trafficJSON {
	home := 0
	if len(a.Inbounds) > 0 {
		home = a.Inbounds[0]
	}
	return trafficJSON{ID: 0, InboundID: home, Enable: a.Enable, Email: a.Email, UUID: "", SubID: a.SubID,
		Up: a.Up, Down: a.Down, AllTime: a.AllTime, Total: a.TotalGB, ExpiryTime: a.ExpiryTime,
		Reset: a.Reset, LastOnline: a.LastOnline}
}

// membersLocked returns the accounts of an inbound sorted by email.
func (s *Store) membersLocked(id int) []*Account {
	var out []*Account
	for _, a := range s.st.Accounts {
		if hasInt(a.Inbounds, id) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// projectInbound renders the old-API object. withClients=false skips the heavy parts.
func (s *Store) projectInboundLocked(in *Inbound, withClients bool) inboundJSON {
	set := map[string]any{}
	for k, v := range in.Settings {
		set[k] = v
	}
	out := inboundJSON{ID: in.ID, Total: in.Total, Remark: in.Remark, Enable: in.Enable,
		ExpiryTime: in.ExpiryTime, Listen: in.Listen, Port: in.Port, Protocol: in.Protocol,
		StreamSettings: "{}", Sniffing: "{}", SortOrder: in.SortOrder,
		Tag: fmt.Sprintf("inbound-%d", in.Port), ClientStats: []trafficJSON{}}
	clients := []clientJSON{}
	if withClients {
		for _, a := range s.membersLocked(in.ID) {
			clients = append(clients, a.client())
			t := a.traffic()
			out.ClientStats = append(out.ClientStats, t)
			out.Up += a.Up
			out.Down += a.Down
		}
	}
	set["clients"] = clients
	b, _ := json.Marshal(set)
	out.Settings = string(b)
	return out
}

func (s *Store) accountByIdentityLocked(inboundID int, ident string) *Account {
	if ident == "" {
		return nil
	}
	if a, ok := s.st.Accounts[ekey(ident)]; ok && (inboundID == 0 || hasInt(a.Inbounds, inboundID)) {
		return a
	}
	for _, a := range s.st.Accounts {
		if inboundID != 0 && !hasInt(a.Inbounds, inboundID) {
			continue
		}
		if a.Password == ident || strings.EqualFold(a.Username, ident) {
			return a
		}
	}
	return nil
}

func newSubID() string { return randHex(8) }

func nowMs() int64 { return time.Now().UnixMilli() }

func itoa(i int) string { return strconv.Itoa(i) }

func (a *Account) expired(now int64) bool { return a.ExpiryTime > 0 && a.ExpiryTime <= now }
func (a *Account) overQuota() bool        { return a.TotalGB > 0 && a.Up+a.Down >= a.TotalGB }

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
