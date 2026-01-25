from datetime import datetime
from rich.console import Console

from netscanner.config import DEFAULT_SUBNET, DEFAULT_PORTS, LOG_FILE, LOG_DIR
from netscanner.utils.netinfo import get_network_info
from netscanner.scanners.live import stream_arp_ports_live
from netscanner.ui.tables import build_network_results_table, print_and_log_table

def run_scan_mode(console: Console, *, subnet: str | None = None, os_scan: bool = True, ports: list[int] | None = None):
    ports_to_check = ports or DEFAULT_PORTS
    net_info = get_network_info(console)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n\n=== Scan Started: {datetime.now()} ===\n")

    scan_subnet = net_info.get("subnet") or (subnet or DEFAULT_SUBNET)

    console.print(
        f"[green]\n\n-----------------------------------------------\n"
        f"[*] Starting ARP Scan on {scan_subnet}...\n"
        f"-----------------------------------------------"
    )

    arp_ports_table, hosts = stream_arp_ports_live(
        console=console,
        subnet=scan_subnet,
        ports=ports_to_check,
        do_os_scan=os_scan
    )

    gw_mac = hosts.get(net_info.get("gateway"))
    net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)

    console.line()
    print_and_log_table(console, arp_ports_table, LOG_FILE)
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
===============================
"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(summary)
        f.write(f"=== Scan Completed: {datetime.now()} ===\n")

    print(summary)
    print(f"[*] Logs saved to: {LOG_FILE.resolve()}")
