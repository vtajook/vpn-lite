#!/usr/bin/env bash
# vpn-lite installer + management menu.
#   bash <(curl -fsSL https://raw.githubusercontent.com/vtajook/vpn-lite/main/install.sh)
# After the first install the same menu is available any time with the command:  vl
#
# Non-interactive use (no menu):
#   install.sh --install [--user U --pass P --port N --domain D --base /x/ --version vX.Y.Z --no-deps]
#   install.sh --update | --uninstall
set -uo pipefail

REPO="${VPN_LITE_REPO:-vtajook/vpn-lite}"
BIN=/usr/local/bin/vpn-lite
MENU_BIN=/usr/local/bin/vl
DATA=/var/lib/vpn-lite
STATE="$DATA/state.json"
DOMAIN_FILE="$DATA/panel.domain"

PORT=""; DOMAIN=""; USER_=""; PASS=""; BASE=""; VERSION="latest"; DEPS=1; ACTION=""
CERT=""; KEY=""

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
have_tty() { [ -r /dev/tty ] && [ -w /dev/tty ]; }
ask() { # ask "prompt" [default]  -> REPLY
  local p="$1" d="${2:-}"
  if have_tty; then read -r -p "$p" REPLY </dev/tty || REPLY=""; else REPLY=""; fi
  REPLY="${REPLY:-$d}"
}
pause() { have_tty && { read -r -p "Press Enter to go back to the menu... " _ </dev/tty || true; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --user) USER_="$2"; shift 2;;
    --pass) PASS="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --no-deps) DEPS=0; shift;;
    --install) ACTION=install; shift;;
    --update) ACTION=update; shift;;
    --uninstall|uninstall) ACTION=uninstall; shift;;
    *) die "unknown option: $1";;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) die "unsupported CPU: $(uname -m)";;
esac

installed() { [ -x "$BIN" ] && [ -f "$STATE" ]; }

# ---------------------------------------------------------------- building blocks

install_deps() { # install_deps force(0|1)
  local force="$1" need=""
  need_pkg() { # need_pkg cmd "packages"
    if [ "$force" = 1 ] || ! command -v "$1" >/dev/null 2>&1; then need="$need $2"; fi
  }
  need_pkg openvpn openvpn
  need_pkg xl2tpd "xl2tpd ppp"
  need_pkg ocserv ocserv
  need_pkg swanctl "strongswan-swanctl charon-systemd"
  need_pkg nft nftables
  need_pkg tc iproute2
  need_pkg curl "curl ca-certificates"
  if [ -n "$need" ]; then
    command -v apt-get >/dev/null || die "missing:$need (install them with your package manager, then use --no-deps)"
    say "installing:$need"
    # Installed WITHOUT starting them: the panel runs its own instances with its own configs.
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq $need
    local rc=$?
    rm -f /usr/sbin/policy-rc.d
    [ $rc = 0 ] || die "package installation failed"
    case "$need" in *ocserv*) systemctl disable --now ocserv.socket ocserv.service >/dev/null 2>&1 || true;; esac
    case "$need" in *xl2tpd*) systemctl disable --now xl2tpd.service >/dev/null 2>&1 || true;; esac
  fi
  modprobe -a tun ppp_generic ppp_async l2tp_ppp pppol2tp 2>/dev/null || true
  if [ ! -e /dev/ppp ] && command -v apt-get >/dev/null; then
    apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
    modprobe -a ppp_generic ppp_async l2tp_ppp pppol2tp 2>/dev/null || true
  fi
  [ -e /dev/ppp ] || warn "/dev/ppp is missing: L2TP will not work on this kernel (OpenVPN and Cisco are unaffected)."
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "ufw is active: open the VPN ports and run: ufw default allow routed"
  fi
}

fetch_binary() {
  local url tmp
  if [ "$VERSION" = latest ]; then url="https://github.com/$REPO/releases/latest/download"
  else url="https://github.com/$REPO/releases/download/$VERSION"; fi
  tmp="$(mktemp -d)"
  say "downloading vpn-lite ($ARCH, $VERSION)"
  curl -fsSL "$url/vpn-lite-linux-$ARCH" -o "$tmp/vpn-lite" || { rm -rf "$tmp"; die "download failed"; }
  curl -fsSL "$url/SHA256SUMS" -o "$tmp/SHA256SUMS" || { rm -rf "$tmp"; die "download failed"; }
  ( cd "$tmp" && grep " vpn-lite-linux-$ARCH\$" SHA256SUMS | sed "s/vpn-lite-linux-$ARCH/vpn-lite/" | sha256sum -c - >/dev/null ) \
    || { rm -rf "$tmp"; die "checksum mismatch, aborting"; }
  install -m 0755 "$tmp/vpn-lite" "$BIN.new" && mv -f "$BIN.new" "$BIN"
  rm -rf "$tmp"
  # keep this menu available as the `vl` command
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/install.sh?$RANDOM" -o "$MENU_BIN.new" 2>/dev/null \
    && [ -s "$MENU_BIN.new" ] && install -m 0755 "$MENU_BIN.new" "$MENU_BIN"
  rm -f "$MENU_BIN.new"
}

host_tuning() {
  modprobe nf_conntrack 2>/dev/null || true
  cat > /etc/sysctl.d/99-vpn-lite.conf <<'SYS'
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = 1048576
SYS
  sysctl -q -p /etc/sysctl.d/99-vpn-lite.conf 2>/dev/null || true
}

write_unit() {
  cat > /etc/systemd/system/vpn-lite.service <<'UNIT'
[Unit]
Description=vpn-lite VPN panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/vpn-lite serve
Restart=always
RestartSec=2
LimitNOFILE=1048576
# Only the panel is stopped/restarted; OpenVPN, xl2tpd and ocserv keep running and are re-adopted.
KillMode=process

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

wipe_runtime() { # stop everything the panel started; remove generated config (NOT the data)
  systemctl stop vpn-lite 2>/dev/null || true
  for f in /run/vpn-lite/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done
  nft delete table ip vpnlite 2>/dev/null || true
}

ask_login() { # fills USER_ PASS PORT when empty
  if [ -z "$USER_" ]; then ask "Admin username [admin]: " admin; USER_="$REPLY"; fi
  if [ -z "$PASS" ]; then
    while :; do
      ask "Admin password (min 8 chars, visible, empty = generate one): " ""
      PASS="$REPLY"
      [ -z "$PASS" ] && break
      [ "${#PASS}" -ge 8 ] && break
      echo "too short, try again"
    done
  fi
  if [ -z "$PORT" ]; then ask "Panel port [2096]: " 2096; PORT="$REPLY"; fi
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

get_cert() { # get_cert domain -> sets CERT KEY, 0 on success
  local d="$1" myip dip
  myip="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  dip="$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1; exit}')"
  say "SSL certificate for $d"
  echo "  domain points to: ${dip:-<not resolved>}   this server: ${myip:-unknown}"
  if [ -n "$dip" ] && [ -n "$myip" ] && [ "$dip" != "$myip" ]; then
    warn "the A record of $d does not point to this server (Cloudflare: turn the proxy OFF / grey cloud)."
  fi
  if ! command -v certbot >/dev/null 2>&1 && command -v apt-get >/dev/null; then
    echo "  installing certbot..."
    apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y certbot >/dev/null || warn "certbot install failed"
  fi
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]80$'; then
    warn "port 80 is busy: $(ss -ltnp 2>/dev/null | grep -E '[:.]80 ' | head -1)"
    return 1
  fi
  command -v certbot >/dev/null 2>&1 || return 1
  if certbot certonly --standalone -d "$d" --agree-tos --register-unsafely-without-email -n --keep-until-expiring; then
    CERT="/etc/letsencrypt/live/$d/fullchain.pem"; KEY="/etc/letsencrypt/live/$d/privkey.pem"
    echo "  certificate OK (renews automatically)"
    return 0
  fi
  return 1
}

resolve_domain() { # tries to get a certificate for $DOMAIN; offers retries; leaves CERT/KEY empty on give-up
  CERT=""; KEY=""
  while [ -n "$DOMAIN" ]; do
    get_cert "$DOMAIN" && return 0
    warn "could not get a certificate for $DOMAIN"
    have_tty || { DOMAIN=""; break; }
    ask "Enter a domain to retry (empty = continue with a self-signed certificate): " ""
    DOMAIN="$REPLY"
  done
  return 1
}

run_setup() { # run_setup <vpn-lite setup args...>; prints and records the panel port
  local out
  systemctl stop vpn-lite 2>/dev/null || true   # a running panel would overwrite the change when it saves
  out="$("$BIN" setup "$@" | tee /dev/stderr)" || die "setup failed"
  PP="$(printf '%s\n' "$out" | sed -n 's/^panel port: \([0-9]*\).*/\1/p' | tail -1)"
}

restart_panel() {
  systemctl enable vpn-lite >/dev/null 2>&1
  systemctl restart vpn-lite
  sleep 1
  systemctl is-active --quiet vpn-lite || { journalctl -u vpn-lite -n 20 --no-pager; die "the panel did not start"; }
}

panel_url() {
  local pp dom host
  pp="$("$BIN" info 2>/dev/null | sed -n 's/^panel port: \([0-9]*\).*/\1/p' | tail -1)"
  dom="$(cat "$DOMAIN_FILE" 2>/dev/null || true)"
  host="${dom:-$(curl -4fsS --max-time 6 https://api.ipify.org 2>/dev/null || echo '<server-ip>')}"
  echo "https://$host:${pp:-2096}/"
}

# ---------------------------------------------------------------- actions

do_install() { # full wizard; on an existing install it is a clean rewrite that keeps accounts/services
  local clean=0
  if [ -f "$STATE" ]; then
    clean=1
    say "clean reinstall (accounts and services are kept)"
    wipe_runtime
    cp -f "$STATE" "$STATE.pre-reinstall" 2>/dev/null || true
    rm -rf /etc/vpn-lite /run/vpn-lite /etc/swanctl/conf.d/vpn-lite.conf /etc/systemd/system/vpn-lite.service /etc/sysctl.d/99-vpn-lite.conf
  fi
  [ "$DEPS" = 1 ] && install_deps "$clean"
  fetch_binary
  host_tuning
  write_unit
  mkdir -p "$DATA"

  echo
  ask_login
  valid_port "$PORT" || die "invalid port: $PORT"
  if [ -z "$DOMAIN" ] && have_tty; then
    ask "Panel domain for HTTPS (empty = use the IP with a self-signed certificate): " ""
    DOMAIN="$REPLY"
  fi
  resolve_domain || true
  if [ -n "$CERT" ]; then printf '%s' "$DOMAIN" > "$DOMAIN_FILE"; else rm -f "$DOMAIN_FILE"; fi

  local args=(-port "$PORT" -user "$USER_")
  [ -n "$PASS" ] && args+=(-pass "$PASS")
  [ -n "$BASE" ] && args+=(-base "$BASE")
  if [ -n "$CERT" ]; then args+=(-cert "$CERT" -key "$KEY"); else args+=(-reset-tls); fi
  say "configuring"
  run_setup "${args[@]}"
  restart_panel
  echo
  say "vpn-lite is running"
  echo "Panel address: $(panel_url)"
  [ -n "$CERT" ] || echo "(self-signed certificate: accept the browser warning, or set a domain from the menu: vl)"
  echo "Open this menu any time with:  vl"
  echo "Import accounts from an old panel:  vpn-lite import -from https://old-host:port/ -user U -pass P -port-shift 10000"
}

do_update() {
  installed || die "vpn-lite is not installed yet"
  fetch_binary
  host_tuning
  write_unit
  restart_panel   # only the panel restarts; tunnels stay up
  say "updated to $("$BIN" version 2>/dev/null | head -1)"
}

do_login() {
  installed || die "vpn-lite is not installed yet"
  USER_=""; PASS=""
  ask "New admin username [admin]: " admin; USER_="$REPLY"
  while :; do
    ask "New admin password (min 8 chars, visible, empty = generate one): " ""
    PASS="$REPLY"; [ -z "$PASS" ] && break; [ "${#PASS}" -ge 8 ] && break; echo "too short, try again"
  done
  local args=(-user "$USER_"); [ -n "$PASS" ] && args+=(-pass "$PASS")
  run_setup "${args[@]}"
  restart_panel
  say "admin login changed"
}

do_port() {
  installed || die "vpn-lite is not installed yet"
  ask "New panel port: " ""
  valid_port "$REPLY" || die "invalid port"
  run_setup -port "$REPLY"
  restart_panel
  say "panel is now at: $(panel_url)"
}

do_domain() {
  installed || die "vpn-lite is not installed yet"
  ask "Panel domain (empty = remove the domain and use a self-signed certificate): " ""
  DOMAIN="$REPLY"
  if [ -z "$DOMAIN" ]; then
    rm -f "$DOMAIN_FILE"; run_setup -reset-tls
  elif resolve_domain; then
    printf '%s' "$DOMAIN" > "$DOMAIN_FILE"; run_setup -cert "$CERT" -key "$KEY"
  else
    warn "no certificate; nothing was changed"; return
  fi
  restart_panel
  say "panel is now at: $(panel_url)"
}

do_status() {
  installed || { echo "vpn-lite is not installed."; return; }
  echo "version:  $("$BIN" version 2>/dev/null | head -1)"
  echo "service:  $(systemctl is-active vpn-lite 2>/dev/null)"
  echo "address:  $(panel_url)"
  echo "daemons:  $(pgrep -c openvpn || true) openvpn, $(pgrep -c xl2tpd || true) xl2tpd, $(pgrep -c ocserv || true) ocserv"
}

do_logs() {
  journalctl -u vpn-lite -n 60 --no-pager
  echo "---- events ----"
  tail -n 30 /var/log/vpn-lite/events.log 2>/dev/null || true
}

do_uninstall() { # do_uninstall purge(0|1)
  say "stopping panel and its VPN daemons"
  systemctl disable --now vpn-lite 2>/dev/null || true
  wipe_runtime
  rm -f /etc/systemd/system/vpn-lite.service "$BIN" /etc/swanctl/conf.d/vpn-lite.conf /etc/sysctl.d/99-vpn-lite.conf
  systemctl daemon-reload
  if [ "$1" = 1 ]; then
    rm -rf "$DATA" /etc/vpn-lite /var/log/vpn-lite /run/vpn-lite "$MENU_BIN"
    echo "everything was removed (including accounts)."
  else
    echo "kept: $DATA (accounts and services). Install again later to continue with them."
  fi
}

confirm() { ask "$1 [y/N]: " ""; case "$REPLY" in y|Y|yes) return 0;; *) return 1;; esac; }

# ---------------------------------------------------------------- entry points

if [ -n "$ACTION" ]; then
  case "$ACTION" in
    install) do_install;;
    update) do_update;;
    uninstall) do_uninstall 0;;
  esac
  exit 0
fi

# Options without an action (old style: --port, --user ...) mean a plain install.
if [ -n "$USER_$PASS$PORT$DOMAIN$BASE" ] || ! have_tty; then
  do_install
  exit 0
fi

while :; do
  clear 2>/dev/null || true
  printf '\033[1;36m'
  echo "  ┌──────────────────────────────────────────┐"
  echo "  │          VPN Lite  -  management         │"
  echo "  └──────────────────────────────────────────┘"
  printf '\033[0m'
  if installed; then echo "  status: $(systemctl is-active vpn-lite 2>/dev/null)   panel: $(panel_url)"; else echo "  status: not installed"; fi
  echo
  echo "   1) Install / reinstall   (asks login, port, domain; keeps accounts)"
  echo "   2) Update                (new version, nothing else changes)"
  echo "   3) Change admin username / password"
  echo "   4) Change panel port"
  echo "   5) Panel domain + SSL certificate"
  echo "   6) Status"
  echo "   7) Restart panel"
  echo "   8) Logs"
  echo "   9) Uninstall             (keeps accounts)"
  echo "  10) Uninstall and delete everything"
  echo "   0) Exit"
  echo
  ask "Choose [0-10]: " ""
  case "$REPLY" in
    1) if installed; then confirm "This rewrites everything except accounts/services. Continue?" && { do_install; pause; }; else do_install; pause; fi;;
    2) do_update; pause;;
    3) do_login; pause;;
    4) do_port; pause;;
    5) do_domain; pause;;
    6) do_status; pause;;
    7) installed && { systemctl restart vpn-lite && say "restarted"; }; pause;;
    8) do_logs; pause;;
    9) confirm "Uninstall vpn-lite (accounts are kept)?" && { do_uninstall 0; pause; };;
    10) confirm "DELETE vpn-lite AND all accounts?" && { do_uninstall 1; pause; };;
    0|q|Q|"") exit 0;;
    *) ;;
  esac
done
