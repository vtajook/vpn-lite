package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// importCmd copies inbounds and accounts from a running vpn-ui panel through its HTTP API
// (the same contract the bot uses), so it needs no access to the old database and cannot
// damage it. Imported inbounds are created DISABLED unless -enable is given, and ports can
// be shifted, so both panels can run side by side until the switch.
func importCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	d := parseDirs(fs)
	from := fs.String("from", "", "old panel URL including base path, e.g. https://host:2053/")
	user := fs.String("user", "", "old panel username")
	pass := fs.String("pass", "", "old panel password")
	shift := fs.Int("port-shift", 0, "add this to every imported inbound port (to run beside the old panel)")
	enable := fs.Bool("enable", false, "create imported inbounds enabled")
	fs.Parse(args)
	if *from == "" || *user == "" || *pass == "" {
		return fmt.Errorf("-from, -user and -pass are required")
	}
	st, err := OpenStore(filepath.Join(d.data, "state.json"))
	if err != nil {
		return err
	}
	defer st.Close()
	nIn, nAcc, skipped, err := importFromPanel(st, *from, *user, *pass, *shift, *enable)
	if err != nil {
		return err
	}
	fmt.Printf("imported %d inbounds and %d accounts (%d clients skipped: no password/email)\n", nIn, nAcc, skipped)
	if !*enable {
		fmt.Println("inbounds were created DISABLED: enable them in the panel when you are ready to switch")
	}
	return nil
}

// importFromPanel copies inbounds and accounts from a running vpn-ui panel into st.
func importFromPanel(st *Store, from, user, pass string, shift int, enable bool) (nIn, nAcc, skipped int, err error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 120 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	base := strings.TrimRight(from, "/")
	resp, e0 := c.PostForm(base+"/login", url.Values{"username": {user}, "password": {pass}})
	if e0 != nil {
		return 0, 0, 0, e0
	}
	var lr envelope
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	if !lr.Success {
		return 0, 0, 0, fmt.Errorf("old panel login refused: %s", lr.Msg)
	}
	req, _ := http.NewRequest("GET", base+"/panel/api/inbounds/list", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err = c.Do(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()
	var list struct {
		Success bool `json:"success"`
		Obj     []struct {
			ID          int    `json:"id"`
			Remark      string `json:"remark"`
			Enable      bool   `json:"enable"`
			Listen      string `json:"listen"`
			Port        int    `json:"port"`
			Protocol    string `json:"protocol"`
			Settings    string `json:"settings"`
			ClientStats []struct {
				Email      string `json:"email"`
				Up         int64  `json:"up"`
				Down       int64  `json:"down"`
				AllTime    int64  `json:"allTime"`
				LastOnline int64  `json:"lastOnline"`
			} `json:"clientStats"`
		} `json:"obj"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil || !list.Success {
		return 0, 0, 0, fmt.Errorf("could not read the inbound list (wrong URL/base path?)")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	idMap := map[int]int{}
	for _, o := range list.Obj {
		if !protoOK[o.Protocol] {
			continue
		}
		set := map[string]any{}
		if json.Unmarshal([]byte(o.Settings), &set) != nil {
			continue
		}
		delete(set, "clients")
		in := &Inbound{ID: st.st.NextInbound, Remark: o.Remark, Enable: o.Enable && enable, Listen: o.Listen,
			Port: o.Port + shift, Protocol: o.Protocol, Settings: set}
		in.SortOrder = in.ID
		st.st.NextInbound++
		st.st.Inbounds[in.ID] = in
		idMap[o.ID] = in.ID
		nIn++
		var cs struct {
			Clients []clientJSON `json:"clients"`
		}
		json.Unmarshal([]byte(o.Settings), &cs)
		stats := map[string]int{}
		for i, s := range o.ClientStats {
			stats[strings.ToLower(s.Email)] = i
		}
		for _, cl := range cs.Clients {
			email := strings.TrimSpace(cl.Email)
			if email == "" || cl.Password == "" {
				skipped++
				continue
			}
			user := strings.TrimSpace(cl.ID)
			if user == "" {
				user = email
			}
			acc := st.st.Accounts[ekey(email)]
			if acc == nil {
				acc = &Account{Email: email, Username: user, Password: cl.Password, SubID: cl.SubID, Enable: cl.Enable,
					TotalGB: cl.TotalGB, ExpiryTime: cl.ExpiryTime, LimitIP: cl.LimitIP, TgID: cl.TgID, Comment: cl.Comment,
					Reset: cl.Reset, SpeedDown: cl.SpeedDown, SpeedUp: cl.SpeedUp, CreatedAt: nowMs()}
				if acc.SubID == "" {
					acc.SubID = newSubID()
				}
				if i, ok := stats[ekey(email)]; ok {
					s := o.ClientStats[i]
					acc.Up, acc.Down, acc.AllTime, acc.LastOnline = s.Up, s.Down, s.AllTime, s.LastOnline
				}
				st.st.Accounts[ekey(email)] = acc
				nAcc++
			}
			// an account may sit on one inbound per protocol
			clash := false
			for _, id := range acc.Inbounds {
				if st.st.Inbounds[id].Protocol == in.Protocol {
					clash = true
				}
			}
			if !clash && !hasInt(acc.Inbounds, in.ID) {
				acc.Inbounds = append(acc.Inbounds, in.ID)
			}
		}
	}
	st.touch()
	return nIn, nAcc, skipped, nil
}
