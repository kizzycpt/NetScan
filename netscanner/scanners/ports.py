import socket
from concurrent.futures import ThreadPoolExecutor
from netscanner.config import DEFAULT_PORTS, PORT_PROTOCOLS


def _probe(ip: str, port: int, timeout: float) -> int | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except OSError:
            return None
    return None


def open_ports_for(ip: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    if not ports:
        return []
    workers = min(len(ports), 100)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: _probe(ip, p, timeout), ports)
    return sorted(p for p in results if p is not None)


def port_scan(ip: str, net_info: dict, ports: list[int] | None = None) -> str:
    ports = ports or DEFAULT_PORTS
    opens = set(open_ports_for(ip, ports, timeout=1.0))

    output = f"\nPort Scan for {ip}:\n"
    output += f"- Gateway: {net_info.get('gateway', 'N/A')}\n"
    output += f"- Subnet: {net_info.get('subnet', 'N/A')}\n"
    output += f"- Public IP: {net_info.get('public_ip', 'N/A')}\n"

    for port in ports:
        status = "OPEN" if port in opens else "CLOSED/FILTERED"
        protocol = PORT_PROTOCOLS.get(port, "Unknown")
        output += f"  Port {port}({protocol}): {status}\n"
    return output
