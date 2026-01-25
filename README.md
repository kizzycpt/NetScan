# NetScan (Network Scanner)

**Network Scanner** is a Python-based LAN discovery + port scanning tool with an optional “IDS mode” that tracks device/port changes over time using a baseline file.

> **Ethical Use Only.** Run this only on networks you own or have explicit permission to test.

---

## What it does

### Scan Mode (one-time snapshot)
- Discovers devices on your local subnet using **ARP**
- Resolves **hostnames** (best-effort)
- Checks a configurable list of **common TCP ports**
- Displays results in a **Rich** table (live/streaming output)
- Writes logs to a local `logs/` folder

### IDS Mode (baseline + alerts)
- Performs a LAN scan repeatedly (example: every 6 hours)
- Stores a baseline (`state.json`) of:
  - devices by **MAC**
  - last seen timestamps
  - open ports
  - gateway MAC
- Generates alerts when it detects:
  - **new devices**
  - **ports opened/closed**
  - **gateway MAC changes**
  - **IP ⇄ MAC mismatches**
  - **devices going offline** (missed runs)

---

## Project layout

Typical structure:

```
NetScan/
├─ main.py / netscan.py         # entrypoint (menu)
├─ netscanner/
│  ├─ __init__.py
│  ├─ config.py                 # constants + paths (logs/reports/default ports)
│  ├─ state.py                  # baseline read/write helpers (state.json)
│  ├─ modes/
│  │  ├─ scan_mode.py           # one-time scan
│  │  └─ ids_mode.py            # baseline + loop + report generation
│  ├─ scanners/
│  │  ├─ arp.py                 # ARP discovery
│  │  ├─ ports.py               # TCP port checks
│  │  ├─ live.py                # streaming Rich table updates
│  │  └─ fingerprint.py         # OS / service hints (optional)
│  ├─ utils/
│  │  ├─ hostnames.py           # hostname resolver
│  │  ├─ netinfo.py             # local/gateway/subnet/public ip helpers
│  │  └─ log.py                 # file logging helpers
│  └─ ui/
│     └─ tables.py              # Rich table builders
└─ logs/
   ├─ scan_log.txt              # rolling scan log
   └─ reports/
      └─ <timestamp>/
         ├─ devices.csv
         ├─ report.md
         └─ console_tables.txt
```

---

## Requirements

- Python 3.10+ (newer versions may work)
- Linux recommended (ARP scanning is simplest)
- **Nmap** (for OS/service fingerprinting via `python-nmap`)

Common Python packages:
- scapy
- rich
- pyfiglet
- requests
- netifaces
- python-nmap

---

## Install

### 1) Clone + virtual environment
```bash
git clone https://github.com/kizzycpt/NetScan
cd NetScan

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) System dependencies (Linux)
```bash
sudo apt update
sudo apt install -y nmap
```

---

## Run

### Menu mode
```bash
python3 main.py
```

If your entry file is still named `netscan.py`:
```bash
python3 netscan.py
```

### Optional shortcuts (if present in your entry script)
```bash
python3 main.py --ids-once
python3 main.py --ids-every 6
```

---

## Where logs save

By default, logs are written relative to the project directory:

- Rolling log:
  - `logs/scan_log.txt`
- IDS run folders:
  - `logs/reports/<timestamp>/`

Each IDS run folder typically includes:
- `devices.csv` (inventory snapshot)
- `report.md` (human-readable summary)
- `console_tables.txt` (tables printed to console, saved without ANSI colors)

---

## Permissions (important)

### ARP scanning needs raw socket access on Linux
If you see:
- `PermissionError: [Errno 1] Operation not permitted`

Run with sudo:
```bash
sudo -E python3 main.py
```

> Why: ARP (Layer 2) requires raw packet privileges.

### OS detection / fingerprinting
Nmap OS fingerprinting (`-O`) often requires elevated privileges (root). If OS details don’t appear, run the tool with sudo, or use the service-hint fallback (banner/version scan).

---

## Troubleshooting

### “circular import” / “partially initialized module”
This usually happens when:
- a file inside `netscanner/` imports from the entry script (`netscan.py` / `main.py`), or
- modules import each other in a loop.

**Rule of thumb**
- Entry script imports `netscanner.*`
- `netscanner/*` should **never** import from the entry script

### “ModuleNotFoundError”
- Ensure your file paths match your import paths (Linux is case-sensitive).
- Ensure packages have `__init__.py` when needed.

---

## Safety + legal disclaimer

This tool is provided for **educational and diagnostic use**.
Do not scan networks you do not own or have explicit permission to test.
You are responsible for how you use this tool.

---

## License
MIT
