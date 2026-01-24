"""
SKO's NETWORK SCANNER
Created by Sam Quarm
Ethical Use Only. For educational and diagnostic purposes.

"""
#Imports
from scapy.all import ARP, Ether, srp, srp1
import time, sys, traceback
import socket
import requests
import netifaces
from datetime import datetime
import nmap
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from rich.table import Table
from rich.live import Live
from rich.console import Console
import pyfiglet
import ipaddress
import re
import signal

#---------------------GLOBAL VARIABLES---------------------



#rich library variables for customization
console = Console()
table = Table()

#functions that need to use args
ARGS = argparse.Namespace(os_scan=False, ports=None, subnet=None, mode=None, out=None)

#Stop_Signal 
STOP_REQUESTED = False


# === Configs === #
DEFAULT_SUBNET = "192.168.1.0/24"
DEFAULT_PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]

BASE_DIR = Path(__file__).parent   # directory where the script lives

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
alerts_file   = LOG_DIR / "alerts.log"
run_directory_format = "%b-%d-%Y_%Hh%Mm" #da "date ran" time stamps


#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


def make_run_dir(root: Path) -> Path:
    #creates a scan ran folder under its root and return the path given
    timestamp = datetime.now().strftime(run_directory_format)
    run_directory = Path(root) / timestamp
    run_directory.mkdir(parents=True, exist_ok=True)
    return run_directory


#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


##---------------------TABLE Functions---------------------


def build_network_results_table(net_info: dict, gw_mac: str | None = None):
    net_table = Table(
        title="\n[!] Network Connection Summary [!]",
        title_style="blue",
        style="blue",
        show_lines=True
    )
    net_table.add_column("Item", style="green", no_wrap=True)
    net_table.add_column("Value", style="green")

    net_table.add_row("Hostname", socket.gethostname())
    net_table.add_row("Local IP", net_info.get("local_ip", "N/A"))
    net_table.add_row("Default Gateway", net_info.get("gateway", "N/A"))
    if gw_mac:
        net_table.add_row("Gateway MAC", gw_mac)
    net_table.add_row("Subnet", net_info.get("subnet", "N/A"))
    net_table.add_row("Public IP", net_info.get("public_ip", "N/A"))
    net_table.add_row("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    return net_table


def build_alerts_table(alerts: list[str]):
    tbl = Table(title="\n[!] Alerts This Run [!]", title_style="blue", style="blue", show_lines=True)
    tbl.add_column("Time", style="green", no_wrap=True)
    tbl.add_column("Severity", style="green")
    tbl.add_column("Type", style="green")
    tbl.add_column("Message", style="green")
    if not alerts:
        tbl.add_row("-", "-", "-", "None")
        return tbl
    for line in alerts:
        try:
            t, sev, typ, msg = line.split(" ", 3)
        except ValueError:
            t, sev, typ, msg = ("", "", "", line)
        tbl.add_row(t, sev, typ, msg)
    return tbl


def build_offline_table(offline_macs: list[str], base_devs: dict):
    tbl = Table(title="\n[!] Offline Devices (this run) [!]", title_style="blue", style="blue", show_lines=True)
    tbl.add_column("MAC", style="green")
    tbl.add_column("Last Seen", style="green")
    tbl.add_column("Missed Runs", style="green")
    if not offline_macs:
        tbl.add_row("-", "-", "-")
        return tbl
    for mac in offline_macs:
        dev = base_devs.get(mac, {})
        tbl.add_row(mac, dev.get("last_seen", "N/A"), str(int(dev.get("missed_runs", 0))))
    return tbl


def build_changes_table(opened_by_mac: dict, closed_by_mac: dict):
    tbl = Table(title="\n[!] Changes Since Last Run [!]", title_style="blue", style="blue", show_lines=True)
    tbl.add_column("MAC", style="green")
    tbl.add_column("Opened", style="green")
    tbl.add_column("Closed", style="green")
    macs = sorted(set(opened_by_mac) | set(closed_by_mac))
    if not macs:
        tbl.add_row("-", "-", "-")
        return tbl
    for mac in macs:
        opened = ", ".join(str(p) for p in opened_by_mac.get(mac, [])) or "-"
        closed = ", ".join(str(p) for p in closed_by_mac.get(mac, [])) or "-"
        tbl.add_row(mac, opened, closed)
    return tbl


def build_inventory_table(current_devices: dict, base_devs: dict, now_iso: str):
    tbl = Table(title="\n[!] Inventory [!]", title_style="blue", style="blue", show_lines=True)
    tbl.add_column("MAC", style="green")
    tbl.add_column("IPs", style="green")
    tbl.add_column("Hostname", style="green")
    tbl.add_column("Open Ports", style="green")
    tbl.add_column("OS Guess", style="green")
    tbl.add_column("First Seen", style="green")
    tbl.add_column("Last Seen", style="green")
    tbl.add_column("Missed Runs", style="green")
    if not current_devices:
        tbl.add_row("-", "-", "-", "-", "-", "-", "-", "-")
        return tbl
    for mac, cur in sorted(current_devices.items()):
        prev = base_devs.get(mac, {})
        first_seen = prev.get("first_seen", now_iso)
        missed = int(prev.get("missed_runs", 0))
        tbl.add_row(
            mac,
            ", ".join(cur.get("ips", [])) or "-",
            cur.get("hostname") or "-",
            ", ".join(str(p) for p in cur.get("open_ports", [])) or "-",
            cur.get("os_guess") or "-",
            first_seen,
            cur.get("last_seen", now_iso),
            str(missed),
        )
    return tbl


def print_and_log_table(rich_table, log_path: Path, width: int = 120):
    # print to terminal
    console.print(rich_table)

    # also write the rendered table to the log file (no ANSI colors)
    from rich.console import Console as RichConsole
    with open(log_path, "a", encoding="utf-8") as f:
        file_console = RichConsole(file=f, no_color=True, width=width, soft_wrap=False)
        file_console.print(rich_table)
        f.write("\n")


def os_guess_for_table(ip: str, enabled: bool = False) -> str:
    if not enabled:
        return "-"
    try:
        scanner = nmap.PortScanner()
        # Let nmap decide ports for OS detection
        scanner.scan(hosts=ip, arguments="-O -Pn -T4")
        if ip in scanner.all_hosts():
            matches = scanner[ip].get("osmatch", [])
            if matches:
                # take best match
                name = matches[0].get("name") or "-"
                acc  = int(matches[0].get("accuracy", 0))
                return f"{name} ({acc}%)" if name else "-"
    except Exception:
        pass
    return "-"


def build_arp_ports_table(hosts: dict[str, str], ports: list[int], do_os_scan: bool = False) -> Table:
    """
    hosts: {ip -> mac}
    ports: list of ports to test (e.g., DEFAULT_PORTS or ARGS.ports)
    """
    tbl = Table(
        title="\n[!] ARP Scan Results [!]",
        title_style="blue",
        style="blue",
        show_lines=True
    )
    tbl.add_column("Host Name", style="green")
    tbl.add_column("IP Address", style="green", no_wrap=True)
    tbl.add_column("MAC Address", style="green", no_wrap=True)
    tbl.add_column("OS", style="green")
    tbl.add_column("Open Ports", style="green")
    tbl.add_column("Closed Ports", style="green")

    def fmt_ports(nums: list[int], color: str) -> str:
        if not nums:
            return "-"
        return "(" + ", ".join(f"[{color}]{p}[/{color}]" for p in nums) + ")"

    for ip, mac in hosts.items():
        hostname = resolve_hostname(ip)

        # port scan
        open_list = open_ports_for(ip, ports)
        closed_list = sorted(set(ports) - set(open_list))

        # OS guess (optional)
        os_guess = os_guess_for_table(ip, enabled=do_os_scan)

        # color the ports
        open_str = fmt_ports(open_list, "green")
        closed_str = fmt_ports(closed_list, "red")

        tbl.add_row(hostname, ip, mac, os_guess, open_str, closed_str)

    return tbl

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#---------------------Resolvers---------------------


def open_ports_for(ip: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    opens = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0:
                opens.append(p)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return sorted(opens)


def resolve_hostname(ip: str) -> str:
    
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass
    if sys.platform.startswith("win"):
        try:
            p = subprocess.run(["nbtstat", "-A", ip],
                            capture_output=True, text=True, timeout=3)
            # Look for lines like: "MYPC            <00>  UNIQUE      Registered"
            for line in p.stdout.splitlines():
                m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                if m:
                    return m.group(1)
        except Exception:
            pass

    try:
        p = subprocess.run(["ping", "-a", "-n", "1", ip],
                        capture_output=True, text=True, timeout=3)
        # "Pinging host.domain [192.168.1.10] with 32 bytes of data:"
        m = re.search(r"Pinging\s+([^\s\[]+)\s+\[", p.stdout)
        if m and m.group(1) and m.group(1) != ip:
            return m.group(1)
    except Exception:
        pass
    return "Unknown"


def udp_top_ports(ip: str, ports="53,67,68,123,137,138,161,1900,5353"):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments=f"-sU -Pn -T4 -p {ports} --max-retries 1 --host-timeout 5s")
        return [int(p) for p, s in scanner[ip].get('udp', {}).items() if s.get('state') == 'open']
    except Exception:
        return []


def stream_arp_ports_live(subnet: str, ports: list[int], do_os_scan: bool) -> tuple[Table, dict[str, str]]:
    """
    Scans the subnet and updates a Rich table row-by-row as hosts reply.
    Returns (final_table, hosts_dict) where hosts_dict is {ip: mac}.
    """
    # Build an initially empty table
    tbl = Table(
        title="\n[!] ARP Scan Results [!]",
        title_style="blue",
        style="blue",
        show_lines=True
    )
    tbl.add_column("Host Name", style="green")
    tbl.add_column("IP Address", style="green", no_wrap=True)
    tbl.add_column("MAC Address", style="green", no_wrap=True)
    tbl.add_column("OS", style="green")
    tbl.add_column("Open Ports", style="green")
    tbl.add_column("Closed Ports", style="green")

    def fmt_ports(nums: list[int], color: str) -> str:
        if not nums:
            return "-"
        return "(" + ", ".join(f"[{color}]{p}[/{color}]" for p in nums) + ")"

    # Track rows and discovered hosts
    rows: list[tuple[str, str, str, str, str, str]] = []
    hosts: dict[str, str] = {}

    # Prepare IPs in the subnet
    discovered = scan_arp(subnet)
    targets = list(discovered.keys())

    # Do ARP -> (hostname, mac) -> ports -> os, in parallel per-IP
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def scan_one(ip: str):
        
        #check for stop
        if STOP_REQUESTED:
            return None

        # ARP request to a single IP
        mac = discovered.get(ip, "_")
        hostname = resolve_hostname(ip)

        # TCP quick check on the configured ports
        open_list = open_ports_for(ip, ports)
        closed_list = sorted(set(ports) - set(open_list))

        # Optional OS fingerprint (via Nmap)
        os_guess = os_guess_for_table(ip, enabled=do_os_scan)

        return (
            hostname or "Unknown",
            ip,
            mac or "-",
            os_guess or "-",
            fmt_ports(open_list, "green"),
            fmt_ports(closed_list, "red"),
        ), (ip, mac)

    # Live table that updates as futures complete
    with Live(tbl, console=console, refresh_per_second=8, transient=True):
        with ThreadPoolExecutor(max_workers=64) as pool:
            futures = [pool.submit(scan_one, ip) for ip in targets]
            for fut in as_completed(futures):
                if STOP_REQUESTED:
                    break

                res = fut.result()

                if res is None:
                    continue
                row, (ip, mac) = res
                rows.append(row)
                hosts[ip] = mac

                #row creation
                tbl.add_row(*row)
    # After live exit, tbl already contains the final rows
    return tbl, hosts


def _handle_sigint(signum, frame):
    """First Ctrl+C: finish this run then exit. Second Ctrl+C: force quit."""
    global STOP_REQUESTED
    if STOP_REQUESTED:
        # user pressed Ctrl+C again -> force immediate KeyboardInterrupt
        raise KeyboardInterrupt
    STOP_REQUESTED = True
    console.print("[yellow]Ctrl+C detected; finishing this run then exiting. Press Ctrl+C again to force quit.[/yellow]")

signal.signal(signal.SIGINT, _handle_sigint)
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#---------------------Scan Functions---------------------


def get_network_info():
    try:
        gws = netifaces.gateways()
        gw_ip, iface = gws['default'][netifaces.AF_INET]
        ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        addr = ip_info['addr']
        mask = ip_info['netmask']
        cidr = str(ipaddress.IPv4Network(f"{addr}/{mask}", strict=False))
        public_ip = requests.get('https://api.ipify.org', timeout=3).text
        return {
            'local_ip': addr,           
            'gateway': gw_ip,
            'subnet': cidr,
            'public_ip': public_ip
        }
    except Exception as e:
        console.print(f"[red][!] Failed to get network info: {e}.[!]")
        return {}


def scan_arp(subnet):
    """Send ARP requests and return discovered hosts."""
    arp = ARP(pdst=subnet)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    
    hosts = {}
    for _, received in result:
        print(f"[+] Host found: {received.psrc} - MAC: {received.hwsrc}")
        hosts[received.psrc] = received.hwsrc
    return hosts


def os_scan(target_ip: str) -> str:
    scanner = nmap.PortScanner()
    out = f"\n--- OS Scan for {target_ip} ---\n"
    try:
        # no -p; let nmap pick probes. keep it bounded.
        scanner.scan(hosts=target_ip,
                     arguments="-O --osscan-guess -Pn -T4 --max-retries 2 --host-timeout 10s")
        if target_ip in scanner.all_hosts():
            matches = scanner[target_ip].get('osmatch', [])
            if matches:
                best = matches[0]
                out += f"OS: {best.get('name','?')} (Accuracy: {best.get('accuracy','0')}%)\n"
            else:
                out += "[!] OS detection failed.\n"
        else:
            out += "[!] Host is down or not responding.\n"
    except Exception as e:
        out += f"[!] OS scan error: {e}\n"
    return out


def port_scan(ip, net_info, ports=DEFAULT_PORTS):
    """Perform TCP port scan."""
    output = f'\nPort Scan for {ip}:\n'
    output += f"- Gateway: {net_info.get('gateway', 'N/A')}\n"
    output += f"- Subnet: {net_info.get('subnet', 'N/A')}\n"
    output += f"- Public IP: {net_info.get('public_ip', 'N/A')}\n"

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                status = "OPEN" if result == 0 else "CLOSED/FILTERED"
                protocol = PORT_PROTOCOLS.get(port, 'Unknown')
                output += f"  Port {port}({protocol}): {status}\n"
        except Exception as e:
            output += f"  Port {port} error: {e}\n"
    return output


def full_host_scan(host, mac_addr, net_info, ports, do_os_scan):
    """Scan a host fully and log results."""

    log += port_scan(host, net_info, ports=use_ports)
    log += f"==== End of {host} ====\n"

    with open(LOG_FILE, 'a') as f:
        f.write(log)


#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


def run_ids_mode(args):
    """
    IDS run:
      - Scan LAN
      - Compare to baseline
      - Write devices.csv + report.md + alerts.log
      - Update baseline for next run
    """
    import json, csv

    now = datetime.now()
    now_iso = now.isoformat(timespec="seconds")

    offline_this_run = []

    # --- Paths / run folder ---
    root = Path(args.out)
    root.mkdir(parents=True, exist_ok=True)
    run_dir = make_run_dir(root)
    devices_csv = run_dir / "devices.csv"
    report_md   = run_dir / "report.md"

    # --- Load baseline ---
    baseline = {
        "last_run_at": None,
        "gateway_ip": None,
        "gateway_mac": None,
        "ip_to_mac": {},
        "devices": {}  # mac -> device dict
    }
    # Proper first-run detection
    is_first_run = not baseline_file.exists()
    if baseline_file.exists():
        try:
            baseline = json.loads(baseline_file.read_text())
        except Exception:
            pass

    # --- Discover current state ---
    net_info = get_network_info()
    subnet   = args.subnet or DEFAULT_SUBNET
    hosts    = scan_arp(subnet)  # dict ip->mac
    gw_ip  = net_info.get("gateway")
    gw_mac = hosts.get(net_info.get("gateway"))

    net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)
    try:
        print_and_log_table(net_tbl, LOG_FILE)
    except NameError:
        console.print(net_tbl)
    
    # -----------------------------------------
    # helpers local to IDS
    # -----------------------------------------
    def open_ports_for(ip, ports):
        opens = []
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((ip, p)) == 0:
                    opens.append(p)
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        return sorted(opens)

    def hostname_for(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def os_guess_for(ip):
        if not getattr(args, "os_scan", False):
            return (None, 0)
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=ip, arguments='-O -Pn -T4')
            if ip in scanner.all_hosts():
                matches = scanner[ip].get('osmatch', [])
                if matches:
                    name = matches[0].get('name')
                    acc  = int(matches[0].get('accuracy', 0))
                    return (name, acc)
        except Exception:
            pass
        return (None, 0)

    ports = args.ports or DEFAULT_PORTS
    current_devices   = {}   # mac -> device dict
    current_ip_to_mac = {}   # ip -> mac (for IP/MAC anomaly)

    # Build current snapshot
    for ip, mac in hosts.items():
        current_ip_to_mac[ip] = mac
        dev = current_devices.setdefault(mac, {
            "mac": mac,
            "ips": set(),
            "hostname": None,
            "open_ports": set(),
            "os_guess": None,
            "first_seen": None,
            "last_seen": None,
            "missed_runs": 0
        })
        dev["ips"].add(ip)

        hn = hostname_for(ip)
        if hn and not dev["hostname"]:
            dev["hostname"] = hn

        opens = open_ports_for(ip, ports)
        dev["open_ports"].update(opens)

        if dev["os_guess"] is None:
            os_name, acc = os_guess_for(ip)
            if os_name and acc >= 80:
                dev["os_guess"] = os_name

    # finalize sets and timestamps
    for dev in current_devices.values():
        dev["ips"]        = sorted(list(dev["ips"]))
        dev["open_ports"] = sorted(list(dev["open_ports"]))
        dev["last_seen"]  = now_iso

    # --- Compare vs baseline -> alerts ---
    alerts = []
    def add_alert(sev, typ, msg):
        alerts.append(f"{now_iso} {sev} {typ} {msg}")

    base_devs  = baseline.get("devices", {})
    base_ip2mac= baseline.get("ip_to_mac", {})
    opened_by_mac = {}
    closed_by_mac = {}

    # 1) Gateway MAC change
    if baseline.get("gateway_mac") and gw_mac and gw_mac != baseline["gateway_mac"]:
        if not is_first_run:
            add_alert("HIGH", "GATEWAY_MAC_CHANGE", f"ip={gw_ip} old={baseline['gateway_mac']} new={gw_mac}")

    # 2) New devices + changes on existing
    SENSITIVE = {22, 23, 445, 3389}
    for mac, cur in current_devices.items():
        if mac not in base_devs:
            if not is_first_run:
                add_alert("HIGH", "NEW_DEVICE", f"mac={mac} ips={cur['ips']} ports={cur['open_ports']}")
        else:
            old = base_devs[mac]
            old_ports = set(old.get("open_ports", []))
            new_ports = set(cur["open_ports"])
            opened = sorted(new_ports - old_ports)
            closed = sorted(old_ports - new_ports)

            if opened:
                opened_by_mac[mac] = opened
                if not is_first_run:
                    sev = "HIGH" if any(p in SENSITIVE for p in opened) else "MEDIUM"
                    add_alert(sev, "PORT_OPENED", f"mac={mac} ips={cur['ips']} opened={opened}")

            if closed:
                closed_by_mac[mac] = closed
                if not is_first_run:
                    add_alert("INFO", "PORT_CLOSED", f"mac={mac} ips={cur['ips']} closed={closed}")

            old_os = old.get("os_guess")
            if cur["os_guess"] and old_os and cur["os_guess"] != old_os:
                if not is_first_run:
                    add_alert("LOW", "OS_CHANGED", f"mac={mac} from={old_os} to={cur['os_guess']}")

    # 3) Offline devices (increment missed_runs)
    for mac, old in base_devs.items():
        if mac not in current_devices:
            offline_this_run.append(mac)
            missed = int(old.get("missed_runs", 0)) + 1
            old["missed_runs"] = missed
            sev = "MEDIUM" if missed >= 3 else "INFO"
            if not is_first_run:
                add_alert(sev, "OFFLINE", f"mac={mac} last_seen={old.get('last_seen')} missed_runs={missed}")

    # 4) IP/MAC anomaly
    for ip, mac in current_ip_to_mac.items():
        if ip in base_ip2mac and base_ip2mac[ip] != mac:
            if not is_first_run:
                add_alert("HIGH", "IP_MAC_MISMATCH", f"ip={ip} old_mac={base_ip2mac[ip]} new_mac={mac}")

    # -------------------------------------------------
    # Rich tables (console + optional per-run log file)
    # -------------------------------------------------
    try:
        net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)
    except NameError:
        net_tbl = None
    arp_ports_tbl = build_arp_ports_table(hosts, ports, do_os_scan=args.os_scan)

    alerts_tbl    = build_alerts_table(alerts)
    offline_tbl   = build_offline_table(offline_this_run, base_devs)
    changes_tbl   = build_changes_table(opened_by_mac, closed_by_mac)
    inventory_tbl = build_inventory_table(current_devices, base_devs, now_iso)

    tables = [t for t in [net_tbl, arp_ports_tbl, alerts_tbl, offline_tbl, changes_tbl, inventory_tbl] if t is not None]

    # Print and also write to run_dir/console_tables.txt if helper exists
    try:
        run_tables_log = run_dir / "console_tables.txt"
        for t in tables:
            print_and_log_table(t, run_tables_log)
    except NameError:
        for t in tables:
            console.print(t)

    # --- Write devices.csv (current devices only) ---
    with open(devices_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["mac", "ips", "hostname", "open_ports", "os_guess", "first_seen", "last_seen", "missed_runs"])
        for mac, cur in sorted(current_devices.items()):
            prev = base_devs.get(mac, {})
            first_seen = prev.get("first_seen", now_iso)
            w.writerow([
                mac,
                ",".join(cur["ips"]),
                cur["hostname"] or "",
                ",".join(str(p) for p in cur["open_ports"]),
                cur["os_guess"] or "",
                first_seen,
                cur["last_seen"],
                0
            ])

    # --- Write report.md (human-readable doc) ---
    new_count     = sum(1 for a in alerts if "NEW_DEVICE" in a)
    offline_count = len(offline_this_run)
    with open(report_md, "w", encoding="utf-8") as f:
        f.write(f"# SKO IDS Report — {now_iso}\n\n")
        f.write("## Network\n")
        f.write(f"- Subnet: {subnet}\n")
        f.write(f"- Gateway: {gw_ip} (MAC: {gw_mac or 'N/A'})\n")
        f.write(f"- Local IP: {net_info.get('local_ip','N/A')}\n")
        f.write(f"- Public IP: {net_info.get('public_ip','N/A')}\n\n")

        f.write("## Summary\n")
        f.write(f"- Devices seen: {len(current_devices)}\n")
        f.write(f"- New devices: {new_count}\n")
        f.write(f"- Offline (this run): {offline_count}\n")
        f.write(f"- Alerts this run: {len(alerts)}\n\n")

        f.write("## Alerts (this run)\n")
        if alerts:
            for line in alerts:
                f.write(f"- {line}\n")
        else:
            f.write("- None\n")
        f.write("\n")

        f.write("## Inventory\n\n")
        f.write("| MAC | IPs | Hostname | Open Ports | OS Guess | First Seen | Last Seen |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for mac, cur in sorted(current_devices.items()):
            prev = base_devs.get(mac, {})
            first_seen = prev.get("first_seen", now_iso)
            f.write(
                f"| {mac} | {', '.join(cur['ips'])} | {cur['hostname'] or ''} | "
                f"{', '.join(str(p) for p in cur['open_ports'])} | {cur['os_guess'] or ''} | "
                f"{first_seen} | {cur['last_seen']} |\n"
            )

        # Changes since last run
        f.write("\n## Changes since last run\n")
        any_changes = False
        for mac in sorted(set(opened_by_mac) | set(closed_by_mac)):
            ops = []
            if mac in opened_by_mac:
                ops.append(f"+opened [{', '.join(str(p) for p in opened_by_mac[mac])}]")
            if mac in closed_by_mac:
                ops.append(f"-closed [{', '.join(str(p) for p in closed_by_mac[mac])}]")
            if ops:
                any_changes = True
                f.write(f"- {mac}: " + "; ".join(ops) + "\n")
        if not any_changes:
            f.write("- None\n")

    # --- Append alerts.log ---
    if alerts:
        alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with open(alerts_file, "a", encoding="utf-8") as f:
            for line in alerts:
                f.write(line + "\n")

    # --- Update & save baseline ---
    new_baseline = {
        "last_run_at": now_iso,
        "gateway_ip": gw_ip,
        "gateway_mac": gw_mac,
        "ip_to_mac": current_ip_to_mac,
        "devices": {}
    }

    # Seen devices: reset missed_runs
    for mac, cur in current_devices.items():
        prev = base_devs.get(mac, {})
        first_seen = prev.get("first_seen", now_iso)
        new_baseline["devices"][mac] = {
            "mac": mac,
            "ips": cur["ips"],
            "hostname": cur["hostname"],
            "open_ports": cur["open_ports"],
            "os_guess": cur["os_guess"],
            "first_seen": first_seen,
            "last_seen": now_iso,
            "missed_runs": 0
        }

    # Unseen devices: carry forward and increment missed_runs
    for mac, prev in base_devs.items():
        if mac not in new_baseline["devices"]:
            nb = dict(prev)
            nb["missed_runs"] = int(prev.get("missed_runs", 0)) + 1
            new_baseline["devices"][mac] = nb

    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    baseline_file.write_text(json.dumps(new_baseline, indent=2))

    print(f"[IDS] Completed. Run folder: {run_dir}")
    print(f"[IDS] Report: {report_md}")


def run_ids_once():
    run_ids_mode(argparse.Namespace(
        subnet=DEFAULT_SUBNET,
        mode="ids",
        out=str(REPORTS_DIR),
        os_scan=True,
        ports=None
    ))


def run_ids_loop(every_hours: float = 6.0):
    global STOP_REQUESTED
    
    interval = float(every_hours) * 3600.0

    args = argparse.Namespace(
        subnet=DEFAULT_SUBNET,
        mode="ids",
        out=str(REPORTS_DIR),
        os_scan=True,
        ports=None,
    )

    console.print(f"[cyan]IDS loop started. It will run every {every_hours} hours.")
    console.print("[cyan]Execute CTRL + C/Break to stop gracefully.[/cyan]")

    try:
        while True:
            start = datetime.now()
            try:
                run_ids_mode(args)
            except Exception as e:
                console.print(f"[red]IDS run failed: {e}[/red]")
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] IDS ERROR: {e}\n")
                    traceback.print_exc(file=f)

            if STOP_REQUESTED:
                console.print("[yellow]Ctrl+C requested stop; exiting IDS loop.[/yellow]")
                break

            # sleep until next run (check for STOP_IDS once per second)
            elapsed = (datetime.now() - start).total_seconds()
            remaining = max(0.0, interval - elapsed)
            console.print(f"[green]Next IDS run in ~{int(remaining // 60)} minutes.[/green]")
            end_time = time.time() + remaining
            while time.time() < end_time:
                if STOP_REQUESTED:
                    break
                time.sleep(1)
    except KeyboardInterrupt:
        pass
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#MAIN EXECUTION

def main():
    global ARGS  # <-- declare ONCE at the top of the function

    title_text = pyfiglet.figlet_format("-----------\n SKO NET SCAN\n----------", font="slant", width=200)
    networkscan_title = pyfiglet.figlet_format("-------------\nNETWORK SCAN\n------------", font="slant", width=200)
    ids_title = pyfiglet.figlet_format("--------------\nIntrusion Detection\n-------------", font="slant", width=200)
    netscan_emoji = r"""
           @@@@@@@@@@@@@@@
       @@@@#+=========+*%@@@
     @@@*===+#@@@@@@@@#====#@@@
   @@@*==*@@#+-::::::-+%@#===#@@
   ====*@#=:::::::::::::::-++=+%@@
 @@+==%%=::::::::::::::::::+@#==%@@
 @#==@%-::::::::::::::::::::=@#==@@@
@@+=#@=:::::::::::::::::::::-*@+=*@@
@%=+@#:::::::::::::::::::::::=%#=+@@
@%=+@*:::::::::::::::::::::::=%%==%@@
@%=+@#::::::::::::::::::::::-=%%=+@@
@@+=%@-:::::::::::::::::::::-*@*=*@@
@@#==@%-:::::::::::::::::::-+%#==%@@
 @@*==@#-::::::::::::::::-=+@%==%@@
  @@*==#@*-::::::::::::--+%@*=+%@@
   @@%+=+#@%*--::----=+#@@*==*@@@@@
     @@%+===#@@@@@@@@@@*===*@@*==#@@@@@
       @@@%+===========+*@@@@%+==*@#-#@@@
          @@@@@@%%%%@@@@@@  @@@%@#-.-#@@@@@
                @@@@         @@@=.:*@#++*%@
                              @@@#@#+====+++#@
                                @@@*=======+*@@@
                                  @@@+=======+#@@@
                                    @@%+======++#@@@
                                      @@%+======+*#@@@
                                       @@@#=======+#@@
                                         @@@#====+%@@
                                           @@@*+%@@
                                             @@@@
"""

   
    console.print(f'[cyan]{netscan_emoji}')
    console.print(f"[cyan]{title_text}")
    console.print("[bold green]1. IDS Mode (baseline + alerts, then exit)")
    console.print("[bold green]2. Scan Mode (one-time snapshot)")
    console.print("[bold green]3. Exit")

    choice = console.input(f"[bold green]Select an option: ").strip()

    if choice == "1":
        console.print(f'[cyan]{netscan_emoji}')
        console.print(f"[cyan]{ids_title}")
        run_ids_loop(6.0)



    elif choice == "2":
        ARGS = argparse.Namespace(
            subnet=DEFAULT_SUBNET,
            mode="scan",
            os_scan=True,        # set True if you want OS guesses via nmap
            ports=None,
            out=str(LOG_DIR),
        )
        console.print(f"[cyan]{netscan_emoji}")
        console.print(f"[cyan]{networkscan_title}")

        net_info = get_network_info()

        with open(LOG_FILE, 'a', encoding="utf-8") as f:
            f.write(f'\n\n=== Scan Started: {datetime.now()} ===\n') 

        scan_subnet = net_info.get("subnet") or (ARGS.subnet or DEFAULT_SUBNET)

        console.print(
            f"[green]\n\n-----------------------------------------------\n"
            f"[*] Starting ARP Scan on {scan_subnet}...\n"
            f"-----------------------------------------------"
        )

        ports_to_check = ARGS.ports or DEFAULT_PORTS

        # Stream rows live; get the final table + discovered hosts
        arp_ports_table, hosts = stream_arp_ports_live(
            subnet=scan_subnet,
            ports=ports_to_check,
            do_os_scan=ARGS.os_scan
        )

        # Build & log the network summary AFTER we know the gateway MAC
        gw_mac = hosts.get(net_info.get("gateway"))
        net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)

       
        console.line()

        print_and_log_table(arp_ports_table, LOG_FILE)

        console.print(net_tbl)                

        


        from rich.console import Console as RichConsole
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            RichConsole(file=f, no_color=True, width=120, soft_wrap=False).print(net_tbl)
            f.write("\n")


        summary = f"""
        ========= SCAN SUMMARY =========
        Total Hosts Found: {len(hosts)}
        Subnet Scanned: {scan_subnet}
        Local IP: {net_info.get('local_ip', 'N/A')}
        Public IP: {net_info.get('public_ip', 'N/A')}
        ================================
        """

        with open(LOG_FILE, 'a', encoding="utf-8") as f:
            f.write(summary)
            f.write(f'=== Scan Completed: {datetime.now()} ===\n')

        print(summary)
        print(f"[*] Logs saved to: {LOG_FILE.resolve()}")



    elif choice == "3":
        print("Exiting...")
        return
    else:
        print("[!] Invalid choice. Try again.")
        main()  # re-run menu if invalid input


        console.print("[yellow]IDS loop interrupted by user (Ctrl+C).[/yellow]")

if __name__ == "__main__":
    if "--ids-once" in sys.argv:
        run_ids_once()
        sys.exit(0)

    if "--ids-every" in sys.argv:
        # Usage: python skonetscan.py --ids-every 6
        try:
            i = sys.argv.index("--ids-every")
            hours = float(sys.argv[i + 1]) if i + 1 < len(sys.argv) else 6.0
        except Exception:
            hours = 6.0
        run_ids_loop(hours)
        sys.exit(0)

    main()
