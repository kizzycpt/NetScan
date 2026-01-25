from scapy.all import ARP, Ether, srp
from rich.console import Console

def scan_arp(console: Console, subnet: str, *, quiet: bool = False) -> dict[str, str]:
    """Broadcast ARP scan: returns {ip: mac}"""
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=2, verbose=0)[0]
    except PermissionError:
        console.print("[red][!] Scapy needs raw-socket permission for ARP on Linux.[/red]")
        console.print("[yellow]Run with sudo, or grant CAP_NET_RAW/CAP_NET_ADMIN to the interpreter.[/yellow]")
        return {}

    hosts: dict[str, str] = {}
    for _, received in result:
        if not quiet:
            print(f"[+] Host found: {received.psrc} - MAC: {received.hwsrc}")
        hosts[received.psrc] = received.hwsrc
    return hosts
