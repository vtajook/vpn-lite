#!/usr/bin/env bash
# vpn-lite installer.  Install / update:
#   bash <(curl -fsSL https://raw.githubusercontent.com/vtajook/vpn-lite/main/install.sh)
# Options:  --port N  --user NAME  --pass PASS  --base /secret/  --version vX.Y.Z
#           --no-deps (do not apt-install daemons)   uninstall
# Re-running updates the binary and restarts the PANEL only: running tunnels stay up.
set -euo pipefail

REPO="${VPN_LITE_REPO:-vtajook/vpn-lite}"
BIN=/usr/local/bin/vpn-lite
PORT=""; USER_=""; PASS=""; BASE=""; VERSION="latest"; DEPS=1; ACTION=install

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --user) USER_="$2"; shift 2;;
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

# ---- daemons --------------------------------------------------------------
# Installed WITHOUT starting them: the panel runs its own instances with its own configs,
# and a distro service must never grab ports 443/1194/1701 behind its back.
if [ "$DEPS" = 1 ]; then
  need=""
  command -v openvpn >/dev/null || need="$need openvpn"
  command -v xl2tpd  >/dev/null || need="$need xl2tpd ppp"
  command -v ocserv  >/dev/null || need="$need ocserv"
  command -v swanctl >/dev/null || need="$need strongswan-swanctl charon-systemd"
  command -v nft     >/dev/null || need="$need nftables"
  command -v tc      >/dev/null || need="$need iproute2"
  command -v curl    >/dev/null || need="$need curl ca-certificates"
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
  fi
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

first=0
[ -f /var/lib/vpn-lite/state.json ] || first=1
args=()
[ -n "$PORT" ] && args+=(-port "$PORT")
[ -n "$USER_" ] && args+=(-user "$USER_")
[ -n "$PASS" ] && args+=(-pass "$PASS")
[ -n "$BASE" ] && args+=(-base "$BASE")
if [ "$first" = 1 ] || [ ${#args[@]} -gt 0 ]; then
  say "configuring"
  "$BIN" setup "${args[@]}"
fi

systemctl enable vpn-lite >/dev/null 2>&1
systemctl restart vpn-lite
sleep 1
systemctl is-active --quiet vpn-lite && say "vpn-lite is running" || { journalctl -u vpn-lite -n 20 --no-pager; exit 1; }
echo
echo "Open the panel at https://<server-ip>:<port>/  (self-signed certificate; the port was printed above)."
echo "Import accounts from the old panel:  vpn-lite import -from https://old-host:port/ -user U -pass P -port-shift 10000"
