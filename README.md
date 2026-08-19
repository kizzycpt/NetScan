# NetScan

> **⚠️ Legacy / archived.** This project is no longer actively developed. Its successor is [sauron](https://github.com/kizzycpt/sauron), which supersedes NetScan's scan + IDS functionality with a fuller dashboard. NetScan remains here as a reference snapshot.

A Python LAN discovery and port-scanning tool with an optional **IDS mode** that baselines the network and alerts on changes over time.

> **Authorized use only.** Run this only on networks you own or have explicit permission to test.

---

## What it does

**Scan mode** — a one-time snapshot:
- Discovers hosts on the local subnet via **ARP** (scapy)
- Resolves hostnames (best-effort)
- Concurrently checks a configurable set of TCP ports per host
- Streams results into a live **Rich** table
- Optional OS fingerprinting via nmap
- Writes a run log to `logs/scan_log.txt`

**IDS mode** — baseline plus alerts:
- Runs a LAN scan on an interval (default every 6 hours)
- Stores a baseline in `state.json` (devices by MAC, IPs, open ports, gateway MAC, last-seen)
- Raises alerts on: new devices, ports opened/closed, gateway MAC changes, IP⇄MAC mismatches, and devices going offline across runs
- Emits a per-run report folder under `logs/reports/<timestamp>/` with `devices.csv`, `report.md`, and `console_tables.txt`

---

## Layout

```
netscan/
├─ netscan.py                   # entrypoint (menu + CLI flags)
├─ state.json                   # IDS baseline (generated)
├─ netscanner/
│  ├─ config.py                 # subnet, ports, paths, protocol map
│  ├─ state.py                  # baseline helpers
│  ├─ modes/
│  │  ├─ scan_mode.py           # one-time scan
│  │  └─ ids_mode.py            # baseline + loop + reports
│  ├─ scanners/
│  │  ├─ arp.py                 # ARP discovery
│  │  ├─ ports.py               # concurrent TCP port checks
│  │  ├─ live.py                # streaming Rich table
│  │  ├─ hostnames.py           # hostname resolution
│  │  └─ os_fingerprint.py      # nmap OS hints
│  ├─ utils/
│  │  ├─ netinfo.py             # local/gateway/subnet/public IP
│  │  └─ signals.py             # Ctrl-C handling
│  └─ ui/
│     ├─ banner.py
│     └─ tables.py
└─ logs/
   ├─ scan_log.txt
   ├─ alerts.log
   └─ reports/<timestamp>/
```

---

## Requirements

- Python 3.10+ (uses `X | None` typing)
- Linux recommended (ARP needs raw sockets)
- `nmap` installed for OS fingerprinting

Python packages: `scapy`, `rich`, `pyfiglet`, `requests`, `netifaces`, `python-nmap`

---

## Install

```bash
git clone https://github.com/kizzycpt/NetScan
cd NetScan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo pacman -S nmap        # or: sudo apt install nmap
```

---

## Run

```bash
sudo -E python3 netscan.py            # interactive menu
sudo -E python3 netscan.py --ids-once # single IDS run
sudo -E python3 netscan.py --ids-every 6   # IDS loop, every 6 hours
```

Menu options: `1` IDS loop (6h) · `2` one-time scan · `3` exit.

`sudo -E` is required because ARP scanning needs raw-socket privileges (`CAP_NET_RAW`). Grant the capability to the interpreter instead of using sudo if you prefer.

Defaults (subnet `192.168.1.0/24`, port list) live in `netscanner/config.py`.

---

## License

MIT
