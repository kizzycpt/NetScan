import socket
from netscanner.config import DEFAULT_PORTS, PORT_PROTOCOLS

def open_ports_for(ip: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    opens: list[int] = []
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

def port_scan(ip: str, net_info: dict, ports: list[int] | None = None) -> str:
    """Text port scan output (used by full_host_scan-style logging)."""
    ports = ports or DEFAULT_PORTS
    output = f"\nPort Scan for {ip}:\n"
    output += f"- Gateway: {net_info.get('gateway', 'N/A')}\n"
    output += f"- Subnet: {net_info.get('subnet', 'N/A')}\n"
    output += f"- Public IP: {net_info.get('public_ip', 'N/A')}\n"

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                status = "OPEN" if result == 0 else "CLOSED/FILTERED"
                protocol = PORT_PROTOCOLS.get(port, "Unknown")
                output += f"  Port {port}({protocol}): {status}\n"
        except Exception as e:
            output += f"  Port {port} error: {e}\n"
    return output
