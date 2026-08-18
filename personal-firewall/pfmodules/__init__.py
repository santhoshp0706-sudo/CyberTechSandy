"""
pfmodules — Personal Firewall package.

Submodules:
  protocol — packet & protocol analysis (IP/TCP/UDP/ICMP parsing)
  rules    — rule engine (allow/block decision making)
  monitor  — live connection monitoring (psutil)
  backend  — OS firewall command generation (iptables / netsh)

Public API:
  evaluate_packet(rules, packet_bytes) -> (decision, details)
"""

from .backend import allow_rule_command, block_rule_command, platform, status_command
from .monitor import list_connections
from .protocol import analyze_packet, demo_packet, service_name
from .rules import Rule, evaluate, load_rules

__all__ = [
    "Rule",
    "load_rules",
    "evaluate",
    "analyze_packet",
    "demo_packet",
    "service_name",
    "list_connections",
    "platform",
    "block_rule_command",
    "allow_rule_command",
    "status_command",
]


def evaluate_packet(rules, packet_bytes) -> tuple:
    """Analyze a raw packet and evaluate it against a rule set.

    Returns (decision, details_dict) where decision is "allow" or "block".
    """
    analysis = analyze_packet(packet_bytes)
    ip = analysis["ip"]
    proto = ip["protocol_name"].lower()
    port = 0
    # strip any trailing IPv4 options? transport parsed already
    transport = analysis["transport"]
    if "tcp" in transport:
        port = transport["tcp"]["dst_port"]
    elif "udp" in transport:
        port = transport["udp"]["dst_port"]

    # direction heuristic: response packets are "in", otherwise "out".
    # For a local test we expose both; default to "out" for a source host.
    decision, matched = evaluate(rules, "in", proto, ip["dst_ip"], port)
    if decision is None and matched is None:
        decision, matched = evaluate(rules, "out", proto, ip["src_ip"], port)
    return decision, matched