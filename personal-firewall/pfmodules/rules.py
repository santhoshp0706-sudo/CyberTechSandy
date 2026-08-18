"""
rules.py — Rule engine for the Personal Firewall.

Rules decide whether a packet/connection should be allowed or blocked.
A rule matches on protocol, direction, IP (optional), and port (optional).

Rule file format (rules/rules.json):
{
  "rules": [
    {"id": "r1", "action": "block", "direction": "in", "proto": "any",
     "ip": "", "port": 0, "note": "default-ish sample"}
  ]
}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

DEFAULT_RULES_FILE = "rules/rules.json"
RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


@dataclass
class Rule:
    id: str
    action: str            # "allow" | "block"
    direction: str         # "in" | "out" | "any"
    proto: str = "any"     # "any" | "tcp" | "udp" | "icmp"
    ip: str = ""           # "" = any IP
    port: int = 0          # 0 = any port
    note: str = ""

    def matches(self, direction: str, proto: str, ip: str = "", port: int = 0) -> bool:
        if self.direction not in ("any", direction):
            return False
        if self.proto not in ("any", proto):
            return False
        if self.ip and ip and self.ip != ip:
            return False
        if self.port and port and self.port != port:
            return False
        return True


def load_rules(path: str = DEFAULT_RULES_FILE) -> list[Rule]:
    """Load rules from a JSON file (relative to the repo root)."""
    # allow an absolute path override
    if not os.path.isabs(path):
        path = os.path.join(RULES_DIR, path) if os.path.exists(os.path.join(RULES_DIR, path)) else path
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [Rule(**r) for r in data.get("rules", [])]


def evaluate(rules: list[Rule], direction: str, proto: str, ip: str = "", port: int = 0) -> tuple[str, Rule | None]:
    """Evaluate rules in order. First match wins. Default = allow when no rule matches."""
    for rule in rules:
        if rule.matches(direction, proto, ip, port):
            return rule.action, rule
    return "allow", None


def describe_rule(rule: Rule) -> str:
    return (f"[{rule.action}] {rule.direction} proto={rule.proto} "
            f"ip={rule.ip or 'any'} port={rule.port or 'any'} ({rule.id})")