package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const releaseRepo = "vtajook/vpn-lite"

func latestRelease() (string, error) {
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get("https://api.github.com/repos/" + releaseRepo + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var j struct {
		Tag string `json:"tag_name"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&j) != nil || j.Tag == "" {
		return "", fmt.Errorf("could not read the latest release (HTTP %d)", resp.StatusCode)
	}
	return j.Tag, nil
}

func download(url string, max int64) ([]byte, error) {
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// selfUpdate downloads the latest release binary, verifies its checksum and replaces the
// running executable. The caller restarts the panel; VPN daemons keep running.
func selfUpdate() (string, error) {
	tag, err := latestRelease()
	if err != nil {
		return "", err
	}
	if tag == version {
		return tag, nil
	}
	name := "vpn-lite-linux-" + runtime.GOARCH
	base := "https://github.com/" + releaseRepo + "/releases/download/" + tag + "/"
	sums, err := download(base+"SHA256SUMS", 1<<20)
	if err != nil {
		return "", err
	}
	bin, err := download(base+name, 200<<20)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bin)
	want := ""
	for _, ln := range strings.Split(string(sums), "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && f[1] == name {
			want = f[0]
		}
	}
	if want == "" || want != hex.EncodeToString(sum[:]) {
		return "", fmt.Errorf("checksum mismatch, update aborted")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", err
	}
	return tag, nil
}

func (a *API) uiUpdateCheck(w http.ResponseWriter, r *http.Request) {
	tag, err := latestRelease()
	if err != nil {
		fail(w, err.Error())
		return
	}
	ok(w, "", map[string]any{"current": version, "latest": tag, "new": tag != version})
}

func (a *API) uiUpdate(w http.ResponseWriter, r *http.Request) {
	tag, err := selfUpdate()
	if err != nil {
		fail(w, err.Error())
		return
	}
	if tag == version {
		ok(w, "already up to date ("+tag+")", nil)
		return
	}
	Events.Add("info", "system", "", "panel updated to %s, restarting", tag)
	ok(w, "updated to "+tag+", restarting", nil)
	go func() { time.Sleep(500 * time.Millisecond); a.st.Flush(); os.Exit(0) }() // systemd starts the new binary
}

func (a *API) uiReboot(w http.ResponseWriter, r *http.Request) {
	Events.Add("info", "system", "", "server reboot requested from the panel")
	ok(w, "rebooting", nil)
	go func() {
		time.Sleep(700 * time.Millisecond)
		a.st.Flush()
		if exec.Command("systemctl", "reboot").Run() != nil {
			exec.Command("reboot").Run()
		}
	}()
}
