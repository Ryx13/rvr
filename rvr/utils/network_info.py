"""
RVR — Network interface helper
Captures attacker IP from tun0 (VPN) or falls back to wlan0/eth0
"""

import subprocess
from typing import Optional, Tuple


def get_attacker_ip() -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (ip_address, interface_name)
    Priority: tun0 -> tun1 -> wlan0 -> eth0
    """
    interfaces = ["tun0", "tun1", "wlan0", "eth0"]

    for iface in interfaces:
        ip = _get_iface_ip(iface)
        if ip:
            return ip, iface

    return None, None


def _get_iface_ip(iface: str) -> Optional[str]:
    """Get IP of a specific interface"""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return None