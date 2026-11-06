package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"
)

// tgAPI is the Bot API base URL (a variable so tests can point it at a fake).
var tgAPI = "https://api.telegram.org"

// backupBytes returns a consistent copy of the state file.
func (s *Store) backupBytes() ([]byte, error) {
	s.Flush()
	return os.ReadFile(s.path)
}

// sendTelegramDocument uploads data as a file to a chat through the Bot API.
func sendTelegramDocument(token, chat, name, caption string, data []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("chat_id", chat)
	if caption != "" {
		mw.WriteField("caption", caption)
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="document"; filename="%s"`, name))
	h.Set("Content-Type", "application/json")
	fw, _ := mw.CreatePart(h)
	fw.Write(data)
	mw.Close()
	req, err := http.NewRequest("POST", tgAPI+"/bot"+token+"/sendDocument", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach Telegram: %v", strings.ReplaceAll(err.Error(), token, "***"))
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &r)
	if !r.OK {
		if r.Description == "" {
			r.Description = resp.Status
		}
		return fmt.Errorf("Telegram refused: %s", r.Description)
	}
	return nil
}

// SendBackup sends the current backup to the configured Telegram chat.
func (s *Store) SendBackup() error {
	s.mu.RLock()
	g := s.st.Global
	nAcc, nIn := len(s.st.Accounts), len(s.st.Inbounds)
	s.mu.RUnlock()
	if g.TgToken == "" || g.TgChat == "" {
		return fmt.Errorf("set the bot token and chat id first")
	}
	data, err := s.backupBytes()
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	name := "vpn-lite-" + time.Now().Format("20060102-1504") + ".json"
	caption := fmt.Sprintf("vpn-lite backup\nserver: %s\naccounts: %d, services: %d\n%s", host, nAcc, nIn, time.Now().Format("2006-01-02 15:04"))
	return sendTelegramDocument(g.TgToken, g.TgChat, name, caption, data)
}

// BackupLoop sends a backup every TgBackupHours hours (0 = off).
func (s *Store) BackupLoop(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var last time.Time
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		s.mu.RLock()
		hours := s.st.Global.TgBackupHours
		on := s.st.Global.TgToken != "" && s.st.Global.TgChat != ""
		s.mu.RUnlock()
		if hours <= 0 || !on {
			last = time.Time{}
			continue
		}
		if last.IsZero() {
			last = time.Now() // first tick after enabling: wait one full interval
			continue
		}
		if time.Since(last) < time.Duration(hours)*time.Hour {
			continue
		}
		last = time.Now()
		if err := s.SendBackup(); err != nil {
			Events.Add("error", "backup", "", "%v", err)
		} else {
			Events.Add("info", "backup", "", "backup sent to Telegram")
		}
	}
}
