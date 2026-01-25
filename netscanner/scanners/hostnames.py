import re
import sys
import socket
import subprocess

def resolve_hostname(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass

    # Windows-only helpers
    if sys.platform.startswith("win"):
        try:
            p = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
            for line in p.stdout.splitlines():
                m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                if m:
                    return m.group(1)
        except Exception:
            pass

        try:
            p = subprocess.run(["ping", "-a", "-n", "1", ip], capture_output=True, text=True, timeout=3)
            m = re.search(r"Pinging\s+([^\s\[]+)\s+\[", p.stdout)
            if m and m.group(1) and m.group(1) != ip:
                return m.group(1)
        except Exception:
            pass
        
    return "Unknown"
