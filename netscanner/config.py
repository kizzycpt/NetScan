from pathlib import Path

# Project root (repo root). netscanner/config.py -> netscan -> root
BASE_DIR = Path(__file__).resolve().parent.parent

# === Configs === #
DEFAULT_SUBNET = "192.168.1.0/24"
DEFAULT_PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]

LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "scan_log.txt"
LOG_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR = LOG_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

PORT_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
}

baseline_file = BASE_DIR / "state.json"
alerts_file = LOG_DIR / "alerts.log"

run_directory_format = "%b-%d-%Y_%Hh%Mm"
