#!/usr/bin/env bash
#
# wifi_security_audit.sh
#
# Read-only home network security audit for macOS.
# Audits YOUR OWN network: WiFi encryption, router config surface,
# connected devices, and your Mac's exposure. Makes no changes and
# never attempts to crack, deauth, or capture credentials.
#
# Usage:
#   chmod +x wifi_security_audit.sh
#   ./wifi_security_audit.sh
#
# Some checks are richer with nmap installed (brew install nmap).
# The script degrades gracefully without it.

set -u

# ----- output helpers -------------------------------------------------------
BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
BLU=$(tput setaf 4 2>/dev/null || true)

REPORT="$HOME/wifi_audit_$(date +%Y%m%d_%H%M%S).txt"

FINDINGS_OK=0
FINDINGS_WARN=0
FINDINGS_CRIT=0

section() { printf '\n%s========== %s ==========%s\n' "$BOLD$BLU" "$1" "$RESET"; }
ok()     { printf '%s[ OK ]%s %s\n' "$GRN" "$RESET" "$1"; FINDINGS_OK=$((FINDINGS_OK+1)); }
warn()   { printf '%s[WARN]%s %s\n' "$YEL" "$RESET" "$1"; FINDINGS_WARN=$((FINDINGS_WARN+1)); }
crit()   { printf '%s[CRIT]%s %s\n' "$RED" "$RESET" "$1"; FINDINGS_CRIT=$((FINDINGS_CRIT+1)); }
info()   { printf '       %s\n' "$1"; }

# Mirror everything to a report file.
exec > >(tee "$REPORT") 2>&1

printf '%sHome Network Security Audit%s\n' "$BOLD" "$RESET"
printf 'Host: %s   Date: %s\n' "$(scutil --get ComputerName 2>/dev/null || hostname)" "$(date)"
printf 'Report saved to: %s\n' "$REPORT"

HAS_NMAP=0
command -v nmap >/dev/null 2>&1 && HAS_NMAP=1

# ----- 1. WiFi interface + encryption --------------------------------------
section "1. WiFi Connection & Encryption"

WIFI_IF=$(networksetup -listallhardwareports 2>/dev/null \
  | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -1)
WIFI_IF=${WIFI_IF:-en0}
info "WiFi interface: $WIFI_IF"

# airport binary is deprecated in recent macOS; try it, then fall back.
AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
SEC=""
SSID=""
if [ -x "$AIRPORT" ]; then
  AP_OUT=$("$AIRPORT" -I 2>/dev/null)
  SSID=$(printf '%s\n' "$AP_OUT" | awk -F': ' '/ SSID/{print $2; exit}')
  SEC=$(printf '%s\n' "$AP_OUT"  | awk -F': ' '/link auth|auth/{print $2; exit}')
fi
# Fallback for macOS versions where airport is gone.
if [ -z "$SSID" ]; then
  SSID=$(ipconfig getsummary "$WIFI_IF" 2>/dev/null \
    | awk -F' : ' '/ SSID/{print $2; exit}')
fi

info "SSID: ${SSID:-unknown}"
info "Reported link auth: ${SEC:-unknown (run 'System Settings > Wi-Fi > Details' to confirm)}"

case "$(printf '%s' "$SEC" | tr '[:upper:]' '[:lower:]')" in
  *wpa3*)            ok   "Encryption is WPA3. Strongest option available." ;;
  *wpa2*)            warn "Encryption is WPA2. Fine today, but enable WPA3 (or WPA2/WPA3 mixed) on the router if supported." ;;
  *wpa*)             crit "Encryption looks like WPA1. This is broken. Switch to WPA2 or WPA3 immediately." ;;
  *wep*)             crit "WEP encryption detected. WEP is trivially crackable. Replace it now." ;;
  *none*|*open*)     crit "Network is OPEN (no encryption). Anyone nearby can read your traffic. Set WPA2/WPA3." ;;
  *)                 info "Could not auto-detect encryption. Verify manually: aim for WPA3, or WPA2 at minimum." ;;
esac

# ----- 2. Gateway / router surface -----------------------------------------
section "2. Router / Gateway"

GW=$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')
info "Default gateway (router): ${GW:-unknown}"

if [ -n "${GW:-}" ]; then
  # Check whether the router admin panel answers on common web ports.
  for PORT in 80 443 8080; do
    if nc -z -G 2 "$GW" "$PORT" >/dev/null 2>&1; then
      info "Router admin interface reachable on port $PORT (http/https). Normal, but see notes."
    fi
  done
  warn "Confirm the router admin password is NOT the default. Default creds are the #1 home-router weakness."
  info "  - Log into http://$GW and change the admin password if you never have."
  info "  - Disable 'Remote Management' / 'WAN admin' so the panel is LAN-only."
  info "  - Check for a firmware update while you are in there."

  # WPS is a known weak point; can't always detect remotely, so flag for manual check.
  warn "Verify WPS (WiFi Protected Setup / push-button pairing) is DISABLED. Its PIN mode is brute-forceable."
  # UPnP exposure check via a light nmap probe if available.
  if [ "$HAS_NMAP" -eq 1 ]; then
    if nmap -sU -p 1900 --open "$GW" 2>/dev/null | grep -qi '1900/udp *open'; then
      warn "UPnP (port 1900) appears open on the router. If you don't need it, disable UPnP to reduce auto port-forwarding risk."
    fi
  fi
else
  warn "Could not determine gateway. Are you connected to WiFi?"
fi

# ----- 3. Devices on the network -------------------------------------------
section "3. Connected Devices"

SUBNET=$(printf '%s' "${GW:-}" | sed 's/\.[0-9]*$/.0\/24/')
info "Local subnet: ${SUBNET:-unknown}"

# Populate the ARP cache with a quick ping sweep (own subnet only).
if [ -n "${GW:-}" ]; then
  BASE=$(printf '%s' "$GW" | sed 's/\.[0-9]*$//')
  for i in $(seq 1 254); do
    ping -c1 -t1 "$BASE.$i" >/dev/null 2>&1 &
  done
  wait
fi

DEVICES=$(arp -a 2>/dev/null | grep -v incomplete)
COUNT=$(printf '%s\n' "$DEVICES" | grep -c . )
info "Devices seen in ARP table: $COUNT"
printf '%s\n' "$DEVICES" | sed 's/^/       /'
info "Review this list. Anything you don't recognize is worth investigating (guest device, neighbor, or IoT you forgot about)."

# ----- 4. This Mac's exposure ----------------------------------------------
section "4. This Mac's Exposure"

# macOS application firewall state.
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if printf '%s' "$FW" | grep -qi enabled; then
  ok "macOS firewall is ON."
else
  warn "macOS firewall is OFF. Turn it on: System Settings > Network > Firewall."
fi

# Sharing services that open listening ports.
info "Checking sharing services..."
SHARING=$(launchctl list 2>/dev/null | grep -Ei 'smbd|afpd|screensharing|ssh|ftp|httpd' )
if [ -n "$SHARING" ]; then
  warn "One or more sharing/remote services are loaded:"
  printf '%s\n' "$SHARING" | awk '{print "       " $3}'
  info "Disable any you don't use: System Settings > General > Sharing."
else
  ok "No common sharing services (SMB/AFP/SSH/screen/FTP) detected as loaded."
fi

# Locally listening ports = your attack surface on the LAN.
info "Ports this Mac is listening on:"
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null \
  | awk 'NR>1{print $1, $9}' | sort -u | sed 's/^/       /'

# ----- 5. Optional deeper self-scan ----------------------------------------
section "5. Optional Self-Scan"
if [ "$HAS_NMAP" -eq 1 ]; then
  MYIP=$(ipconfig getifaddr "$WIFI_IF" 2>/dev/null)
  if [ -n "$MYIP" ]; then
    info "Scanning this Mac ($MYIP) for open TCP ports (top 100)..."
    nmap -T4 --top-ports 100 --open "$MYIP" 2>/dev/null \
      | grep -E 'open|Nmap scan' | sed 's/^/       /'
    info "Every open port is something reachable from your LAN. Close what you don't need."
  fi
else
  info "nmap not installed. For a deeper self-scan: brew install nmap"
fi

# ----- summary --------------------------------------------------------------
section "Summary"
printf 'OK: %s   Warnings: %s   Critical: %s\n' "$FINDINGS_OK" "$FINDINGS_WARN" "$FINDINGS_CRIT"
printf '\nTop hardening checklist:\n'
cat <<'EOF'
  1. Use WPA3 (or WPA2/WPA3 mixed). Never WEP/WPA1/open.
  2. Change the router admin password off the default. Use a long unique one.
  3. Disable WPS, and disable remote/WAN management.
  4. Keep router firmware current. Enable auto-update if offered.
  5. Use a strong WiFi passphrase (15+ chars, random).
  6. Put IoT / smart-home gear on a separate guest or IoT SSID.
  7. Keep the macOS firewall on and turn off sharing services you don't use.
  8. Reboot the router periodically and audit the device list monthly.
EOF
printf '\nReport saved to: %s\n' "$REPORT"
