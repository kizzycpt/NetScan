import json
import csv
import time
import traceback
import socket
from datetime import datetime
from pathlib import Path
from rich.console import Console

import nmap

from netscanner.config import (
    DEFAULT_SUBNET, DEFAULT_PORTS,
    baseline_file, alerts_file,
    REPORTS_DIR, LOG_FILE,
    run_directory_format
)
from netscanner.utils.netinfo import get_network_info
from netscanner.scanners.arp import scan_arp
from netscanner.scanners.ports import open_ports_for
from netscanner.ui.tables import (
    build_network_results_table, build_alerts_table,
    build_offline_table, build_changes_table,
    build_inventory_table, build_arp_ports_table,
    print_and_log_table
)
from netscanner.utils.signals import STOP_REQUESTED

def make_run_dir(root: Path) -> Path:
    timestamp = datetime.now().strftime(run_directory_format)
    run_directory = Path(root) / timestamp
    run_directory.mkdir(parents=True, exist_ok=True)
    return run_directory

def run_ids_mode(console: Console, args):
    now = datetime.now()
    now_iso = now.isoformat(timespec="seconds")
    offline_this_run = []

    root = Path(args.out)
    root.mkdir(parents=True, exist_ok=True)
    run_dir = make_run_dir(root)
    devices_csv = run_dir / "devices.csv"
    report_md = run_dir / "report.md"

    baseline = {
        "last_run_at": None,
        "gateway_ip": None,
        "gateway_mac": None,
        "ip_to_mac": {},
        "devices": {}
    }
    is_first_run = not baseline_file.exists()
    if baseline_file.exists():
        try:
            baseline = json.loads(baseline_file.read_text())
        except Exception:
            pass

    net_info = get_network_info(console)
    subnet = args.subnet or DEFAULT_SUBNET

    hosts = scan_arp(console, subnet, quiet=False)
    gw_ip = net_info.get("gateway")
    gw_mac = hosts.get(net_info.get("gateway"))

    net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)
    print_and_log_table(console, net_tbl, LOG_FILE)

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
            scanner.scan(hosts=ip, arguments="-O -Pn -T4")
            if ip in scanner.all_hosts():
                matches = scanner[ip].get("osmatch", [])
                if matches:
                    name = matches[0].get("name")
                    acc = int(matches[0].get("accuracy", 0))
                    return (name, acc)
        except Exception:
            pass
        return (None, 0)

    ports = args.ports or DEFAULT_PORTS
    current_devices = {}
    current_ip_to_mac = {}

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

    for dev in current_devices.values():
        dev["ips"] = sorted(list(dev["ips"]))
        dev["open_ports"] = sorted(list(dev["open_ports"]))
        dev["last_seen"] = now_iso

    alerts = []
    def add_alert(sev, typ, msg):
        alerts.append(f"{now_iso} {sev} {typ} {msg}")

    base_devs = baseline.get("devices", {})
    base_ip2mac = baseline.get("ip_to_mac", {})
    opened_by_mac = {}
    closed_by_mac = {}

    if baseline.get("gateway_mac") and gw_mac and gw_mac != baseline["gateway_mac"]:
        if not is_first_run:
            add_alert("HIGH", "GATEWAY_MAC_CHANGE", f"ip={gw_ip} old={baseline['gateway_mac']} new={gw_mac}")

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

    for mac, old in base_devs.items():
        if mac not in current_devices:
            offline_this_run.append(mac)
            missed = int(old.get("missed_runs", 0)) + 1
            old["missed_runs"] = missed
            sev = "MEDIUM" if missed >= 3 else "INFO"
            if not is_first_run:
                add_alert(sev, "OFFLINE", f"mac={mac} last_seen={old.get('last_seen')} missed_runs={missed}")

    for ip, mac in current_ip_to_mac.items():
        if ip in base_ip2mac and base_ip2mac[ip] != mac:
            if not is_first_run:
                add_alert("HIGH", "IP_MAC_MISMATCH", f"ip={ip} old_mac={base_ip2mac[ip]} new_mac={mac}")

    arp_ports_tbl = build_arp_ports_table(hosts, ports, do_os_scan=args.os_scan)
    alerts_tbl = build_alerts_table(alerts)
    offline_tbl = build_offline_table(offline_this_run, base_devs)
    changes_tbl = build_changes_table(opened_by_mac, closed_by_mac)
    inventory_tbl = build_inventory_table(current_devices, base_devs, now_iso)

    run_tables_log = run_dir / "console_tables.txt"
    for t in [arp_ports_tbl, alerts_tbl, offline_tbl, changes_tbl, inventory_tbl]:
        print_and_log_table(console, t, run_tables_log)

    with open(devices_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["mac","ips","hostname","open_ports","os_guess","first_seen","last_seen","missed_runs"])
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

    new_count = sum(1 for a in alerts if "NEW_DEVICE" in a)
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

    if alerts:
        alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with open(alerts_file, "a", encoding="utf-8") as f:
            for line in alerts:
                f.write(line + "\n")

    new_baseline = {
        "last_run_at": now_iso,
        "gateway_ip": gw_ip,
        "gateway_mac": gw_mac,
        "ip_to_mac": current_ip_to_mac,
        "devices": {}
    }

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

    for mac, prev in base_devs.items():
        if mac not in new_baseline["devices"]:
            nb = dict(prev)
            nb["missed_runs"] = int(prev.get("missed_runs", 0)) + 1
            new_baseline["devices"][mac] = nb

    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    baseline_file.write_text(json.dumps(new_baseline, indent=2))

    print(f"[IDS] Completed. Run folder: {run_dir}")
    print(f"[IDS] Report: {report_md}")

def run_ids_once(console: Console):
    class A: pass
    args = A()
    args.subnet = DEFAULT_SUBNET
    args.out = str(REPORTS_DIR)
    args.os_scan = True
    args.ports = None
    run_ids_mode(console, args)

def run_ids_loop(console: Console, every_hours: float = 6.0):
    interval = float(every_hours) * 3600.0

    class A: pass
    args = A()
    args.subnet = DEFAULT_SUBNET
    args.out = str(REPORTS_DIR)
    args.os_scan = True
    args.ports = None

    console.print(f"[cyan]IDS loop started. It will run every {every_hours} hours.")
    console.print("[cyan]Execute CTRL + C/Break to stop gracefully.[/cyan]")

    try:
        while True:
            start = datetime.now()
            try:
                run_ids_mode(console, args)
            except Exception as e:
                console.print(f"[red]IDS run failed: {e}[/red]")
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] IDS ERROR: {e}\n")
                    traceback.print_exc(file=f)

            if STOP_REQUESTED:
                console.print("[yellow]Ctrl+C requested stop; exiting IDS loop.[/yellow]")
                break

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
