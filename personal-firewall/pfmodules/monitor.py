"""
monitor.py — Live connection monitor for the Personal Firewall.

Uses `psutil` to enumerate active TCP/UDP connections and label them with
protocol, direction (relative to this host), local/remote address, PID.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

USER_TUPLE_KEYS = ("AF_INET", "AF_INET6")


@dataclass
class Connection:
    proto: str
    direction: str
    local: tuple
    remote: tuple
    pid: int | None
    status: str = ""

    @property
    def remote_port(self) -> int | None:
        return self.remote[1] if self.remote else None

    @property
    def remote_ip(self) -> str | None:
        return self.remote[0] if self.remote else None


def iter_connections(kind: str = "inet") -> Iterator[Connection]:
    """Yield Connection objects from psutil.net_connections."""
    import psutil
    import socket as _socket

    for c in psutil.net_connections(kind=kind):
        try:
            proto = "TCP" if c.type == _socket.SOCK_STREAM else "UDP"
            remote = tuple(c.raddr) if c.raddr else None
            # A connection with a remote peer is outbound; otherwise inbound (LISTEN / UDP bind).
            direction = "out" if remote else "in"
            yield Connection(
                proto=proto,
                direction=direction,
                local=tuple(c.laddr),
                remote=remote,
                pid=c.pid,
                status=c.status,
            )
        except Exception:  # skip unparseable entries
            continue


def list_connections(kind: str = "inet") -> list[str]:
    """Return a formatted list of active connections (best effort)."""
    lines = []
    for c in iter_connections(kind=kind):
        local = f"{c.local[0]}:{c.local[1]}"
        remote = f"{c.remote[0]}:{c.remote[1]}" if c.remote else (c.status or "-")
        lines.append(
            f"{c.proto:<4} {c.direction:<4} {local:<22} -> {remote:<26} pid={c.pid}"
        )
    return lines