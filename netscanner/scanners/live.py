from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.live import Live
from rich.console import Console

from netscanner.scanners.arp import scan_arp
from netscanner.scanners.hostnames import resolve_hostname
from netscanner.scanners.ports import open_ports_for
from netscanner.scanners.os_fingerprint import os_guess_for_table
from netscanner.utils.signals import STOP_REQUESTED

def stream_arp_ports_live(console: Console, subnet: str, ports: list[int], do_os_scan: bool) -> tuple[Table, dict[str, str]]:
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

    rows: list[tuple[str, str, str, str, str, str]] = []
    hosts: dict[str, str] = {}

    discovered = scan_arp(console, subnet, quiet=True)
    targets = list(discovered.keys())

    def scan_one(ip: str):
        if STOP_REQUESTED:
            return None

        mac = discovered.get(ip, "-")
        hostname = resolve_hostname(ip)

        open_list = open_ports_for(ip, ports)
        closed_list = sorted(set(ports) - set(open_list))

        os_guess = os_guess_for_table(ip, enabled=do_os_scan)

        return (
            hostname or "Unknown",
            ip,
            mac or "-",
            os_guess or "-",
            fmt_ports(open_list, "green"),
            fmt_ports(closed_list, "red"),
        ), (ip, mac)

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
                tbl.add_row(*row)

    return tbl, hosts
