"""
protocol.py — Packet & protocol analysis for the Personal Firewall.

Parses raw IP / TCP / UDP / ICMP headers and performs basic protocol analysis.
Works with raw bytes captured from a raw socket or scapy. A `--demo` mode is
included so you can exercise the parser without root/admin privileges.

Skills: protocol analysis, packet decomposition, port/service mapping.
"""

from __future__ import annotations

import ipaddress
import socket
import struct

# Well-known ports → service names (subset for analysis)
SERVICE_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT", 69: "TFTP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NETBIOS-NS",
    143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "SYSLOG", 636: "LDAPS",
    853: "DNS-TLS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "ORACLE", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 9090: "HTTP-ALT", 27017: "MongoDB",
}

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def service_name(port: int) -> str:
    """Return the service name for a well-known port."""
    if port in SERVICE_PORTS:
        return SERVICE_PORTS[port]
    try:
        return socket.getservbyport(port)
    except (OSError, OverflowError):
        return "unknown"


def parse_ip_header(data: bytes) -> dict:
    """Parse the IPv4 header (20 bytes) from raw packet bytes."""
    if len(data) < 20:
        raise ValueError("packet too short for IP header")
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    ttl, proto, checksum = data[8], data[9], struct.unpack("!H", data[10:12])[0]
    src = ipaddress.ip_address(data[12:16])
    dst = ipaddress.ip_address(data[16:20])
    if len(data) < ihl:
        raise ValueError("packet too short for declared IP header length")
    payload = data[ihl:]
    return {
        "version": version,
        "ihl": ihl,
        "ttl": ttl,
        "protocol": proto,
        "protocol_name": IP_PROTOCOLS.get(proto, f"proto-{proto}"),
        "src_ip": str(src),
        "dst_ip": str(dst),
        "payload": payload,
    }


def parse_tcp_header(payload: bytes) -> dict:
    """Parse the TCP header (20 bytes) from the IP payload."""
    if len(payload) < 20:
        raise ValueError("payload too short for TCP header")
    src_port, dst_port, seq, ack = struct.unpack("!HHII", payload[:12])
    offset_flags = payload[12]
    data_offset = (offset_flags >> 4) * 4
    flags = payload[13]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "flags": flags,
        "flags_human": describe_tcp_flags(flags),
        "service": service_name(dst_port),
    }


def parse_udp_header(payload: bytes) -> dict:
    """Parse the UDP header (8 bytes) from the IP payload."""
    if len(payload) < 8:
        raise ValueError("payload too short for UDP header")
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", payload[:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "service": service_name(dst_port),
    }


def parse_icmp_header(payload: bytes) -> dict:
    """Parse the ICMP header (type/code) from the IP payload."""
    if len(payload) < 4:
        raise ValueError("payload too short for ICMP header")
    icmp_type, code, checksum = struct.unpack("!BBH", payload[:4])
    return {"type": icmp_type, "code": code, "checksum": checksum}


def describe_tcp_flags(fl: int) -> str:
    names = {"URG": 0x20, "ACK": 0x10, "PSH": 0x08, "RST": 0x04, "SYN": 0x02, "FIN": 0x01}
    return "+".join(name for name, bit in names.items() if fl & bit) or "NONE"


def analyze_packet(data: bytes) -> dict:
    """Full analysis of a raw packet: IP + transport header."""
    ip = parse_ip_header(data)
    transport = {}
    if ip["protocol_name"] == "TCP":
        transport = {"tcp": parse_tcp_header(ip["payload"])}
    elif ip["protocol_name"] == "UDP":
        transport = {"udp": parse_udp_header(ip["payload"])}
    elif ip["protocol_name"] == "ICMP":
        transport = {"icmp": parse_icmp_header(ip["payload"])}
    return {"ip": ip, "transport": transport}


# ---------------------------------------------------------------------------
# Demo packets (valid-syntax IPv4/TCP/UDP/ICMP), no privileges required
# ---------------------------------------------------------------------------
def demo_packet(proto: str) -> bytes:
    from ctypes import c_ubyte

    # Build a minimal IPv4 header (20 bytes) with a TCP/UDP/ICMP payload
    total_len = 20 + 20
    ver_ihl = 0x45
    # version=4, ihl=5 → 0x45
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0,          # version/ihl, TOS=0
        total_len, 0x1234, 0,  # total length, id, flags/frag
        64, proto, 0,         # TTL, protocol, checksum (0)
        socket.inet_aton("192.168.1.10"),
        socket.inet_aton("8.8.8.8"),
    )
    if proto == 6:
        payload = struct.pack("!HHIIBBHHH", 49152, 443, 1000, 2000, 5 << 4, 0x12, 65535, 0, 0)
    elif proto == 17:
        payload = struct.pack("!HHHH", 49153, 53, 8, 0)
    elif proto == 1:
        payload = struct.pack("!BBH", 8, 0, 0)
    else:
        raise ValueError(f"unsupported demo proto: {proto}")
    body = header + payload
    # fix total length to actual size
    body = body[:2] + struct.pack("!H", len(body)) + body[4:]
    return body