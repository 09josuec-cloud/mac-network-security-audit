#!/usr/bin/env bash
#
# network_vuln_audit.sh   (v2, deep)
#
# Deep, READ-ONLY vulnerability audit of YOUR OWN home network on macOS.
#
# What it does:
#   - WiFi layer: real encryption/PHY/channel, plus duplicate-SSID / rogue-AP check
#   - This Mac: every listening port mapped to its process, LAN-facing vs localhost
#   - Full TCP port + service/version scan of this Mac (all 65535 ports)
#   - nmap vuln-detection scripts against this Mac and the gateway
#   - UDP top-ports sweep
#   - SMB signing, UPnP/SSDP, and TLS cipher checks where those services exist
#   - Subnet inventory, with an opt-in deep scan of every host
#
# What it does NOT do:
#   - No WPA handshake capture, no deauth, no WPS brute force, no evil twin.
#   - No credential guessing or exploitation. Detection and fingerprinting only.
#
# Targets are derived from YOUR gateway/subnet. Only run this on a network
# you own or administer.
#
# Usage:
#   chmod +x network_vuln_audit.sh
#   ./network_vuln_audit.sh            # interactive; asks before the intrusive parts
#   sudo ./network_vuln_audit.sh       # unlocks SYN scan, OS detection, UDP
#
# nmap is required for the deep parts:  brew install nmap

set -u

BOLD=$(tput bold 2>/dev/null || true); RESET=$(tput sgr0 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true); GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true); BLU=$(tput setaf 4 2>/dev/null || true)

REPORT="$HOME/network_vuln_audit_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1

section(){ printf '\n%s========== %s ==========%s\n' "$BOLD$BLU" "$1" "$RESET"; }
ok(){   printf '%s[ OK ]%s %s\n' "$GRN" "$RESET" "$1"; }
warn(){ printf '%s[WARN]%s %s\n' "$YEL" "$RESET" "$1"; }
crit(){ printf '%s[CRIT]%s %s\n' "$RED" "$RESET" "$1"; }
info(){ printf '       %s\n' "$1"; }

ask(){ # ask "question" -> returns 0 for yes. Defaults to NO if not a tty.
  if [ ! -t 0 ]; then return 1; fi
  printf '%s[?]%s %s [y/N] ' "$YEL" "$RESET" "$1"; read -r a
  case "$a" in [Yy]*) return 0;; *) return 1;; esac
}

printf '%sDeep Network Vulnerability Audit%s\n' "$BOLD" "$RESET"
printf 'Host: %s   Date: %s\n' "$(scutil --get ComputerName 2>/dev/null || hostname)" "$(date)"
printf 'Report: %s\n' "$REPORT"

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
SUDO=""; [ "$IS_ROOT" -eq 0 ] && SUDO="sudo"
HAS_NMAP=0; command -v nmap >/dev/null 2>&1 && HAS_NMAP=1
if [ "$HAS_NMAP" -eq 0 ]; then
  warn "nmap not found. Deep scans will be skipped. Install with: brew install nmap"
fi

WIFI_IF=$(networksetup -listallhardwareports 2>/dev/null | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -1)
WIFI_IF=${WIFI_IF:-en0}
MYIP=$(ipconfig getifaddr "$WIFI_IF" 2>/dev/null)
GW=$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')
BASE=$(printf '%s' "${GW:-}" | sed 's/\.[0-9]*$//')
SUBNET="${BASE:-192.168.0}.0/24"

info "Interface: $WIFI_IF   This Mac: ${MYIP:-unknown}   Gateway: ${GW:-unknown}   Subnet: $SUBNET"

# ---------------------------------------------------------------------------
section "1. WiFi Layer"
# system_profiler reports the real security type even when the old airport CLI can't.
SP=$(system_profiler SPAirPortDataType 2>/dev/null)
CUR=$(printf '%s\n' "$SP" | awk '/Current Network Information:/{f=1} f&&/:/{print} /Other Local Wi-Fi Networks:/{f=0}')
CUR_SSID=$(printf '%s\n' "$CUR" | awk 'NR==2{gsub(/^ +| +$|:$/,"");print}')
CUR_SEC=$(printf '%s\n'  "$CUR" | awk -F': ' '/Security:/{print $2; exit}')
CUR_PHY=$(printf '%s\n'  "$CUR" | awk -F': ' '/PHY Mode:/{print $2; exit}')
CUR_CH=$(printf '%s\n'   "$CUR" | awk -F': ' '/Channel:/{print $2; exit}')
info "SSID: ${CUR_SSID:-unknown}   PHY: ${CUR_PHY:-?}   Channel: ${CUR_CH:-?}"
info "Security: ${CUR_SEC:-unknown}"
case "$(printf '%s' "$CUR_SEC" | tr '[:upper:]' '[:lower:]')" in
  *wpa3*) ok   "WPA3 in use. Strongest available." ;;
  *wpa2*) warn "WPA2. Acceptable. Enable WPA3 (or WPA2/WPA3 mixed) in the eero app if all clients support it." ;;
  *wep*|*wpa\ *|*wpa:*) crit "Legacy WPA/WEP. Replace immediately." ;;
  *none*|*open*) crit "OPEN network, no encryption." ;;
  *) info "Could not parse security. Check System Settings > Wi-Fi > Details." ;;
esac
# Duplicate-SSID / rogue-AP indicator: same network name advertised more than once
# with different security is a classic evil-twin sign.
if [ -n "${CUR_SSID:-}" ]; then
  DUPES=$(printf '%s\n' "$SP" | grep -F "$CUR_SSID" | wc -l | tr -d ' ')
  if [ "${DUPES:-0}" -gt 1 ]; then
    warn "Your SSID name appears $DUPES times in the scan. Multiple BSSIDs are normal for mesh (eero has several). Only worry if one shows a DIFFERENT security type than the rest."
  fi
fi

# ---------------------------------------------------------------------------
section "2. This Mac: Listening Services"
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if printf '%s' "$FW" | grep -qi enabled; then ok "macOS firewall ON."
else crit "macOS firewall OFF. Enable it: System Settings > Network > Firewall, and turn on Stealth Mode."; fi
STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
printf '%s' "$STEALTH" | grep -qi enabled && ok "Stealth mode ON." || warn "Stealth mode OFF (Mac answers pings/probes)."

info "LAN-facing listeners (reachable from other devices):"
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1, $9}' \
  | grep -Ev '127\.0\.0\.1|\[::1\]' | sort -u | sed 's/^/       /'
info "Localhost-only listeners (NOT network-reachable, informational):"
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1, $9}' \
  | grep -E '127\.0\.0\.1|\[::1\]' | sort -u | sed 's/^/       /'

# ---------------------------------------------------------------------------
section "3. Deep Scan: This Mac"
if [ "$HAS_NMAP" -eq 1 ] && [ -n "${MYIP:-}" ]; then
  SCANTYPE="-sT"; EXTRA=""
  if [ "$IS_ROOT" -eq 1 ]; then SCANTYPE="-sS"; EXTRA="-O"; fi
  info "Full TCP port + version scan (all 65535 ports). This can take several minutes..."
  $SUDO nmap $SCANTYPE -sV $EXTRA -p- --open -T4 "$MYIP" 2>/dev/null \
    | grep -E 'open|Nmap scan|OS details|Running:' | sed 's/^/       /'
  if ask "Run nmap vuln-detection scripts against this Mac? (slower, safe/read-only)"; then
    info "Running --script vuln ..."
    $SUDO nmap -sV --script vuln -T4 "$MYIP" 2>/dev/null \
      | grep -E 'open|\|' | sed 's/^/       /'
  fi
  if [ "$IS_ROOT" -eq 1 ]; then
    info "UDP top-50 scan..."
    nmap -sU --top-ports 50 --open -T4 "$MYIP" 2>/dev/null \
      | grep -E 'open|Nmap scan' | sed 's/^/       /'
  else
    info "Run with sudo to include UDP scan and OS detection."
  fi
else
  info "Skipped (needs nmap and a WiFi IP)."
fi

# ---------------------------------------------------------------------------
section "4. Gateway / eero"
if [ "$HAS_NMAP" -eq 1 ] && [ -n "${GW:-}" ]; then
  info "Scanning gateway $GW (eero exposes very little by design)..."
  $SUDO nmap -sV -p- --open -T4 "$GW" 2>/dev/null \
    | grep -E 'open|Nmap scan' | sed 's/^/       /'
  info "UPnP/SSDP check..."
  $SUDO nmap -sU -p1900 --script upnp-info "$GW" 2>/dev/null \
    | grep -E 'open|1900|\|' | sed 's/^/       /'
  info "Note: eero is cloud-managed and normally shows no admin ports. Open admin ports here would be unusual."
fi

# ---------------------------------------------------------------------------
section "5. Subnet Inventory"
if [ "$HAS_NMAP" -eq 1 ]; then
  info "Host discovery on $SUBNET ..."
  LIVE=$($SUDO nmap -sn -T4 "$SUBNET" 2>/dev/null | awk '/Nmap scan report/{print $NF}' | tr -d '()')
  printf '%s\n' "$LIVE" | sed 's/^/       /'
  N=$(printf '%s\n' "$LIVE" | grep -c .)
  info "$N live hosts."
  if ask "Deep service scan EVERY host on the subnet? (thorough; can be slow and may poke flaky IoT)"; then
    for H in $LIVE; do
      printf '\n%s   --- %s ---%s\n' "$BOLD" "$H" "$RESET"
      $SUDO nmap -sV --top-ports 1000 --open -T4 "$H" 2>/dev/null \
        | grep -E 'open|MAC Address' | sed 's/^/       /'
    done
  else
    info "Skipped per-host deep scan. Re-run and answer y to inventory every device's open services."
  fi
else
  info "Skipped (needs nmap)."
fi

# ---------------------------------------------------------------------------
section "6. Targeted Service Checks"
if [ "$HAS_NMAP" -eq 1 ]; then
  # SMB signing on anything sharing over 445 (self + gateway as a quick pass)
  for H in "$MYIP" "$GW"; do
    [ -z "$H" ] && continue
    SMB=$($SUDO nmap -p445 --script smb-security-mode,smb2-security-mode "$H" 2>/dev/null | grep -iE 'message_signing|445/tcp')
    if printf '%s' "$SMB" | grep -qi open; then
      info "SMB on $H:"; printf '%s\n' "$SMB" | sed 's/^/         /'
    fi
  done
  # TLS cipher quality on this Mac if it serves https anywhere
  if lsof -nP -iTCP:443 -sTCP:LISTEN >/dev/null 2>&1; then
    info "TLS ciphers on this Mac:443 ..."
    $SUDO nmap --script ssl-enum-ciphers -p443 "$MYIP" 2>/dev/null | grep -E '\|' | sed 's/^/       /'
  fi
fi

# ---------------------------------------------------------------------------
section "Summary & Hardening"
cat <<'EOF'
  This Mac
    [ ] Firewall ON + Stealth mode ON
    [ ] Turn off Screen Sharing / Remote Login if unused (Settings > General > Sharing)
    [ ] Close or firewall any unexpected LAN-facing listener from section 2/3
  eero (all in the app)
    [ ] 2FA on the eero/Amazon account  (this is your "admin password")
    [ ] Software update current
    [ ] WPA3 (or WPA2/WPA3 mixed) enabled
    [ ] Guest network on; move IoT / smart-home devices to it
    [ ] Review the named device list; pause anything unknown
  General
    [ ] Strong random WiFi passphrase (15+ chars)
    [ ] Re-run this audit monthly and compare the device list
EOF
printf '\nReport saved to: %s\n' "$REPORT"
