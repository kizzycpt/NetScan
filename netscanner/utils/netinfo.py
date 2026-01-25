import ipaddress
import requests
import netifaces
from rich.console import Console

def get_network_info(console: Console) -> dict:
    try:
        gws = netifaces.gateways()
        gw_ip, iface = gws["default"][netifaces.AF_INET]
        ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        addr = ip_info["addr"]
        mask = ip_info["netmask"]
        cidr = str(ipaddress.IPv4Network(f"{addr}/{mask}", strict=False))
        public_ip = requests.get("https://api.ipify.org", timeout=3).text
        return {"local_ip": addr, "gateway": gw_ip, "subnet": cidr, "public_ip": public_ip}
    except Exception as e:
        console.print(f"[red][!] Failed to get network info: {e}.[!]")
        return {}
