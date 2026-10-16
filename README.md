# Mac Network Security Audit

Two Bash scripts I wrote to check my own home network and Mac for common security weaknesses. They run on macOS, make no changes, and save a full report to a text file.

Only run these on a network you own or administer.

## The scripts

### `wifi_security_audit.sh` (quick check)

A fast, read only audit that works without extra tools and gets richer if nmap is installed.

1. **WiFi connection and encryption:** which security mode the network uses (flags open, WEP, or WPA1 networks)
2. **Router and gateway:** which admin services the router exposes, with a reminder to change default passwords
3. **Connected devices:** a list of devices on the local network
4. **This Mac's exposure:** listening ports, firewall status, and sharing services
5. **Optional self scan:** a deeper nmap scan of the Mac
6. **Summary:** counts of OK, WARN, and CRIT findings with next steps

### `network_vuln_audit.sh` (deep check)

A deeper audit built on nmap. It asks before running the more intrusive scans.

1. **WiFi layer:** encryption, channel, and a check for duplicate network names that could point to a rogue access point
2. **Listening services:** every open port on the Mac mapped to the process using it, split into network facing and local only
3. **Deep scan of the Mac:** all 65,535 TCP ports with service and version detection, plus nmap's vulnerability scripts
4. **Gateway:** the same checks against the router, plus a UPnP/SSDP check
5. **Subnet inventory:** every device on the network, with an opt in deep scan of each one
6. **Targeted service checks:** SMB signing and TLS cipher checks where those services exist
7. **Summary and hardening checklist**

## What they do not do

* No WiFi password cracking, handshake capture, deauth attacks, or WPS brute force
* No password guessing or exploitation. Detection and fingerprinting only.
* No changes to the Mac, the router, or any device

## Usage

```bash
brew install nmap                 # needed for the deep scans

chmod +x wifi_security_audit.sh network_vuln_audit.sh

./wifi_security_audit.sh          # quick audit
./network_vuln_audit.sh           # deep audit, asks before intrusive steps
sudo ./network_vuln_audit.sh      # also runs SYN scan, OS detection, and UDP scan
```

Each run saves a timestamped report in your home folder, for example `~/network_vuln_audit_20261015_221500.txt`.

## Output

Findings are color coded so problems stand out. Example lines from the scripts:

```
[ OK ] macOS firewall is ON.
[WARN] Confirm the router admin password is NOT the default. Default creds are the #1 home-router weakness.
[CRIT] WEP encryption detected. WEP is trivially crackable. Replace it now.
```

## Built with

* Bash, using built in macOS tools (`networksetup`, `ipconfig`, `lsof`, `arp`, and the macOS application firewall)
* nmap for port, service, and vulnerability scanning
