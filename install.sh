#!/usr/bin/env bash
# vpn-lite installer.  Install / update:
#   bash <(curl -fsSL https://raw.githubusercontent.com/vtajook/vpn-lite/main/install.sh)
# Options:  --port N  --user NAME  --domain panel.example.com  --pass PASS  --base /secret/  --version vX.Y.Z
#           --no-deps (do not apt-install daemons)   uninstall
# Re-running updates the binary and restarts the PANEL only: running tunnels stay up.
set -euo pipefail

REPO="${VPN_LITE_REPO:-vtajook/vpn-lite}"
BIN=/usr/local/bin/vpn-lite
PORT=""; DOMAIN=""; USER_=""; PASS=""; BASE=""; VERSION="latest"; DEPS=1; ACTION=install

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --user) USER_="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --reconfigure) RECONF=1; shift;;
    --pass) PASS="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --no-deps) DEPS=0; shift;;
    uninstall) ACTION=uninstall; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

if [ "$ACTION" = uninstall ]; then
  say "stopping panel and its VPN daemons"
  systemctl disable --now vpn-lite 2>/dev/null || true
  for f in /run/vpn-lite/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done
  nft delete table ip vpnlite 2>/dev/null || true
  rm -f /etc/systemd/system/vpn-lite.service "$BIN" /etc/swanctl/conf.d/vpn-lite.conf
  systemctl daemon-reload
  echo "kept: /var/lib/vpn-lite (accounts) and /etc/vpn-lite. Delete them by hand if you want a clean slate."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1;;
esac

# ---- existing install: clean rewrite -------------------------------------
# Interactive run without options on an existing install = reinstall everything (packages, binary,
# service, configs, certificates, login, port) and keep ONLY the data: accounts and services.
first=0
[ -f /var/lib/vpn-lite/state.json ] || first=1
CLEAN=0
if [ "$first" = 0 ] && [ -r /dev/tty ] && [ -z "$USER_$PASS$PORT$DOMAIN" ]; then first=1; CLEAN=1; fi
if [ "$CLEAN" = 1 ]; then
  say "clean reinstall (accounts and services are kept)"
  systemctl stop vpn-lite 2>/dev/null || true
  for f in /run/vpn-lite/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done
  nft delete table ip vpnlite 2>/dev/null || true
  rm -rf /etc/vpn-lite /run/vpn-lite /etc/swanctl/conf.d/vpn-lite.conf /etc/systemd/system/vpn-lite.service /etc/sysctl.d/99-vpn-lite.conf
  cp -f /var/lib/vpn-lite/state.json "/var/lib/vpn-lite/state.json.pre-reinstall" 2>/dev/null || true
fi

# ---- daemons --------------------------------------------------------------
# Installed WITHOUT starting them: the panel runs its own instances with its own configs,
# and a distro service must never grab ports 443/1194/1701 behind its back.
if [ "$DEPS" = 1 ]; then
  need=""
  { [ "$CLEAN" = 1 ] || ! command -v openvpn >/dev/null; } && need="$need openvpn"
  { [ "$CLEAN" = 1 ] || ! command -v xl2tpd  >/dev/null; } && need="$need xl2tpd ppp"
  { [ "$CLEAN" = 1 ] || ! command -v ocserv  >/dev/null; } && need="$need ocserv"
  { [ "$CLEAN" = 1 ] || ! command -v swanctl >/dev/null; } && need="$need strongswan-swanctl charon-systemd"
  { [ "$CLEAN" = 1 ] || ! command -v nft     >/dev/null; } && need="$need nftables"
  { [ "$CLEAN" = 1 ] || ! command -v tc      >/dev/null; } && need="$need iproute2"
  { [ "$CLEAN" = 1 ] || ! command -v curl    >/dev/null; } && need="$need curl ca-certificates"
  if [ -n "$need" ]; then
    command -v apt-get >/dev/null || { echo "missing:$need (install them with your package manager, then re-run with --no-deps)" >&2; exit 1; }
    say "installing:$need"
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
    trap 'rm -f /usr/sbin/policy-rc.d' EXIT
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq $need
    rm -f /usr/sbin/policy-rc.d
    # Distro packages enable their own services (ocserv even via a socket on :443, xl2tpd on :1701),
    # which would grab our ports at the next boot. The panel runs its own instances instead.
    case "$need" in *ocserv*) systemctl disable --now ocserv.socket ocserv.service >/dev/null 2>&1 || true;; esac
    case "$need" in *xl2tpd*) systemctl disable --now xl2tpd.service >/dev/null 2>&1 || true;; esac
  fi

  # PPP needs /dev/ppp; minimal cloud kernels (Ubuntu linux-kvm, ...) ship the modules in an extra package.
  modprobe -a tun ppp_generic ppp_async l2tp_ppp pppol2tp 2>/dev/null || true
  if [ ! -e /dev/ppp ] && command -v apt-get >/dev/null; then
    apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
    modprobe -a ppp_generic ppp_async l2tp_ppp pppol2tp 2>/dev/null || true
  fi
  [ -e /dev/ppp ] || echo "WARNING: /dev/ppp is missing: L2TP will not work on this kernel (OpenVPN and Cisco are unaffected)." >&2
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "NOTE: ufw is active. Open the VPN ports and allow forwarding: ufw default allow routed" >&2
fi

# ---- binary ---------------------------------------------------------------
if [ "$VERSION" = latest ]; then URL="https://github.com/$REPO/releases/latest/download"; else URL="https://github.com/$REPO/releases/download/$VERSION"; fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"; rm -f /usr/sbin/policy-rc.d' EXIT
say "downloading vpn-lite ($ARCH, $VERSION)"
curl -fsSL "$URL/vpn-lite-linux-$ARCH" -o "$tmp/vpn-lite"
curl -fsSL "$URL/SHA256SUMS" -o "$tmp/SHA256SUMS"
( cd "$tmp" && grep " vpn-lite-linux-$ARCH\$" SHA256SUMS | sed "s/vpn-lite-linux-$ARCH/vpn-lite/" | sha256sum -c - >/dev/null ) \
  || { echo "checksum mismatch, aborting" >&2; exit 1; }
install -m 0755 "$tmp/vpn-lite" "$BIN.new"
mv -f "$BIN.new" "$BIN"

# ---- host tuning ----------------------------------------------------------
modprobe nf_conntrack 2>/dev/null || true
cat > /etc/sysctl.d/99-vpn-lite.conf <<'SYS'
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = 1048576
SYS
sysctl -q -p /etc/sysctl.d/99-vpn-lite.conf 2>/dev/null || true

# ---- service --------------------------------------------------------------
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

# Ask for the admin login on a first install / reconfigure (skipped when given as options or when there is no terminal).
if [ "$first" = 1 ] && [ -r /dev/tty ] && { [ -z "$USER_" ] || [ -z "$PASS" ] || [ -z "$PORT" ]; }; then
  echo
  if [ -z "$USER_" ]; then
    read -r -p "Admin username [admin]: " USER_ </dev/tty || true
    USER_="${USER_:-admin}"
  fi
  if [ -z "$PASS" ]; then
    while :; do
      read -r -s -p "Admin password (min 8 chars, empty = generate one): " PASS </dev/tty || true; echo
      [ -z "$PASS" ] && break
      if [ "${#PASS}" -lt 8 ]; then echo "too short, try again"; continue; fi
      read -r -s -p "Repeat password: " PASS2 </dev/tty || true; echo
      [ "$PASS" = "$PASS2" ] && break
      echo "passwords differ, try again"; PASS=""
    done
  fi
  if [ -z "$PORT" ]; then
    read -r -p "Panel port [2096]: " PORT </dev/tty || true
    PORT="${PORT:-2096}"
  fi
fi
# Optional panel domain: get a free Let's Encrypt certificate for it (needs the domain's A record
# pointing here and port 80 free for a moment).
if [ "$first" = 1 ] && [ -z "$DOMAIN" ] && [ -r /dev/tty ]; then
  read -r -p "Panel domain for HTTPS (empty = use the IP with a self-signed certificate): " DOMAIN </dev/tty || true
fi
CERT=""; KEY=""
if [ -n "$DOMAIN" ]; then
  say "getting an SSL certificate for $DOMAIN"
  if [ "$DEPS" = 1 ] && ! command -v certbot >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null 2>&1 || true
  fi
  if ss -ltn 2>/dev/null | grep -q ':80 '; then
    echo "WARNING: port 80 is in use; free it and run again with --domain $DOMAIN"
  elif command -v certbot >/dev/null 2>&1 && \
     certbot certonly --standalone -d "$DOMAIN" --agree-tos --register-unsafely-without-email -n --keep-until-expiring; then
    CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    echo "certificate OK (renews automatically)"
  else
    echo "WARNING: could not get a certificate (is the A record of $DOMAIN pointing to this server?). Using a self-signed one."
  fi
fi
args=()
[ -n "$CERT" ] && args+=(-cert "$CERT" -key "$KEY")
[ "$CLEAN" = 1 ] && args+=(-reset-tls)
[ -n "$PORT" ] && args+=(-port "$PORT")
[ -n "$USER_" ] && args+=(-user "$USER_")
[ -n "$PASS" ] && args+=(-pass "$PASS")
[ -n "$BASE" ] && args+=(-base "$BASE")
say "configuring"
SETUP_OUT="$("$BIN" setup "${args[@]}" | tee /dev/stderr)"
PP="$(printf '%s\n' "$SETUP_OUT" | sed -n 's/^panel port: \([0-9]*\).*/\1/p' | tail -1)"

systemctl enable vpn-lite >/dev/null 2>&1
systemctl restart vpn-lite
sleep 1
systemctl is-active --quiet vpn-lite && say "vpn-lite is running" || { journalctl -u vpn-lite -n 20 --no-pager; exit 1; }
echo
if [ -n "$CERT" ]; then echo "Open the panel at https://$DOMAIN:${PP:-2096}/"
else echo "Open the panel at https://<server-ip>:${PP:-2096}/  (self-signed certificate: accept the browser warning)."; fi
echo "Import accounts from the old panel:  vpn-lite import -from https://old-host:port/ -user U -pass P -port-shift 10000"
