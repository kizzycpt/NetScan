import socket
from datetime import datetime
from pathlib import Path
from rich.table import Table
from rich.console import Console as RichConsole

from netscanner.scanners.hostnames import resolve_hostname
from netscanner.scanners.ports import open_ports_for
from netscanner.scanners.os_fingerprint import os_guess_for_table

def build_network_results_table(net_info: dict, gw_mac: str | None = None) -> Table:
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

def build_alerts_table(alerts: list[str]) -> Table:
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

def build_offline_table(offline_macs: list[str], base_devs: dict) -> Table:
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

def build_changes_table(opened_by_mac: dict, closed_by_mac: dict) -> Table:
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

def build_inventory_table(current_devices: dict, base_devs: dict, now_iso: str) -> Table:
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

def print_and_log_table(console, rich_table: Table, log_path: Path, width: int = 120):
    console.print(rich_table)
    with open(log_path, "a", encoding="utf-8") as f:
        file_console = RichConsole(file=f, no_color=True, width=width, soft_wrap=False)
        file_console.print(rich_table)
        f.write("\n")

def build_arp_ports_table(hosts: dict[str, str], ports: list[int], do_os_scan: bool = False) -> Table:
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
        open_list = open_ports_for(ip, ports)
        closed_list = sorted(set(ports) - set(open_list))
        os_guess = os_guess_for_table(ip, enabled=do_os_scan)

        open_str = fmt_ports(open_list, "green")
        closed_str = fmt_ports(closed_list, "red")
        tbl.add_row(hostname, ip, mac, os_guess, open_str, closed_str)

    return tbl
