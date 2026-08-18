"""
backend.py — OS-level firewall backend (command generation).

These functions return the exact command an administrator should run to
enforce a rule:
  * Linux  → iptables
  * Windows → netsh advfirewall

The firewall itself never silently executes blocking commands (to avoid
locking the user out); it prints the commands with admin context.
"""

from __future__ import annotations

import sys


def platform() -> str:
    return "windows" if sys.platform.startswith("win") else "linux"


def block_rule_command(direction: str, proto: str, port: int = 0, ip: str = "") -> str:
    """Return the backend command to block traffic."""
    if platform() == "windows":
        rname = f"PFW-Block-{direction}-{proto}-{port or 'any'}"
        if port:
            return (f'netsh advfirewall firewall add rule name="{rname}" '
                    f'dir={direction} action=block protocol={proto} '
                    f'remoteip={ip or "any"} localport={port}')
        return (f'netsh advfirewall firewall add rule name="{rname}" '
                f'dir={direction} action=block protocol={proto} '
                f'remoteip={ip or "any"}')
    # linux
    if proto == "icmp":
        return f"iptables -A INPUT -p icmp -j DROP"
    if port:
        return f"iptables -A INPUT -p {proto} --dport {port} -j DROP"
    return f"iptables -A INPUT -p {proto} -j DROP"


def allow_rule_command(direction: str, proto: str, port: int = 0, ip: str = "") -> str:
    """Return the backend command to allow traffic."""
    if platform() == "windows":
        rname = f"PFW-Allow-{direction}-{proto}-{port or 'any'}"
        if port:
            return (f'netsh advfirewall firewall add rule name="{rname}" '
                    f'dir={direction} action=allow protocol={proto} '
                    f'remoteip={ip or "any"} localport={port}')
        return (f'netsh advfirewall firewall add rule name="{rname}" '
                f'dir={direction} action=allow protocol={proto} '
                f'remoteip={ip or "any"}')
    if port:
        return f"iptables -A INPUT -p {proto} --dport {port} -j ACCEPT"
    return f"iptables -A INPUT -p {proto} -j ACCEPT"


def status_command() -> str:
    if platform() == "windows":
        return "netsh advfirewall firewall show rule name=all"
    return "iptables -L -n -v"