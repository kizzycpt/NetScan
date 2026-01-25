import nmap
import os
import subprocess

def os_guess_for_table(ip: str, enabled: bool = False) -> str:
    if not enabled:
        return "-"

    try:
        # call nmap directly with sudo for OS detection only
        cmd = ["sudo", "-n", "nmap", "-O", "--osscan-guess", "-Pn", "-T4",
               "--max-retries", "2", "--host-timeout", "10s", ip]
        p = subprocess.run(cmd, capture_output=True, text=True)

        if p.returncode != 0:
            # -n means "non-interactive"; if sudo needs a password you'll see it here
            return "[!] Sudo Required [!]"

        # crude parse: look for "OS details:" or "Running:"
        for line in p.stdout.splitlines():
            if line.startswith("OS details:"):
                return line.replace("OS details:", "").strip()
            if line.startswith("Running:"):
                return line.replace("Running:", "").strip()

        return "-"
    except Exception as e:
        return f"OS_ERR: {e}"


def os_hint_from_services(ip: str) -> str:
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-sV -Pn -T4 --version-light --host-timeout 10s")
        if ip not in nm.all_hosts():
            return "-"

        tcp = nm[ip].get("tcp", {})
        hints = []
        for port, info in tcp.items():
            product = info.get("product")
            name    = info.get("name")
            ver     = info.get("version")
            if product:
                hints.append(f"{name}:{product} {ver}".strip())

        return "; ".join(hints[:2]) if hints else "-"
    except Exception:
        return "-"


def os_scan(target_ip: str) -> str:
    scanner = nmap.PortScanner()
    out = f"\n--- OS Scan for {target_ip} ---\n"
    try:
        scanner.scan(
            hosts=target_ip,
            arguments="-O --osscan-guess -Pn -T4 --max-retries 2 --host-timeout 10s"
        )
        if target_ip in scanner.all_hosts():
            matches = scanner[target_ip].get("osmatch", [])
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
