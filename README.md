# vpn-lite

A small, fast VPN account panel for **OpenVPN, L2TP (IPsec + plain) and Cisco/OpenConnect**, with the same HTTP API the Telegram bot already uses (`/login`, `/panel/api/inbounds/...`). One static Go binary, no database server, no Xray.

## Install (any Debian/Ubuntu server)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vtajook/vpn-lite/main/install.sh) --port 2096
```

It installs the daemons (without starting them), downloads the binary from GitHub Releases, creates the service, makes a self-signed HTTPS certificate and prints the admin password. Run it again to update: only the panel restarts, tunnels stay up.
Options: `--port N --user NAME --pass PASS --base /secret/ --version vX.Y.Z --no-deps`, and `uninstall`.

## Move from the old panel (no downtime until you choose)

```bash
# 1. copy accounts; inbounds are created DISABLED and shifted to other ports
vpn-lite import -from https://OLD-HOST:PORT/ -user OLD_USER -pass OLD_PASS -port-shift 10000
# 2. open the new panel, enable ONE inbound (e.g. OpenVPN) on its shifted port and test a real login
# 3. when happy: stop that protocol on the old panel, set the real port on the new inbound, enable it
# 4. point the bot at the new panel (URL, user, password only; no code change)
```
Run the import again just before the switch to refresh traffic counters.
L2TP/IPsec uses fixed UDP 500/4500 and 1701, so test L2TP on another port first (plain L2TP) and switch IPsec at cutover.

## Design

| Concern | How |
|---|---|
| OpenVPN login | `management-client-auth`: the daemon asks the panel over a local socket; no `auth-user-pass-verify`/`client-connect` scripts, so no exec in OpenVPN's event loop |
| L2TP / Cisco login | built-in RADIUS server on 127.0.0.1 (PAP, CHAP, MS-CHAPv2) for pppd and ocserv; modems that only speak PAP/CHAP work |
| IPsec for phones | strongSwan (swanctl), IKEv1 PSK, transport mode on UDP/1701; plain L2TP on the same port keeps working |
| Traffic | OpenVPN `bytecount`, RADIUS accounting; quota/expiry kicks run within seconds |
| Device limit | per account or per inbound; `evict` never drops a session younger than the grace window (no ping-pong), or `reject` |
| Speed limit | per account, `tc` on the session's device (TBF for ppp/ocserv, HTB class for the shared OpenVPN tun) |
| Panel restart | daemons are separate processes and are re-adopted; sessions are rebuilt from `status 3` |
| State | one JSON file, atomic writes, `.bak` of the previous generation, in-memory index |
| HTTPS | built in; certificate reloaded from disk (certbot/acme.sh renewals need no restart) |

## Files
`/var/lib/vpn-lite/state.json` accounts and settings (back it up from Settings → Backup) · `/etc/vpn-lite` generated daemon configs · `/var/log/vpn-lite/events.log` every login, rejection, kick and disconnect with the reason.
