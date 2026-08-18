"""
firewall.py — Personal Firewall master CLI.

Usage:
  python firewall.py monitor                 # list active connections (needs psutil)
  python firewall.py inspect tcp             # parse & analyze a synthetic TCP packet
  python firewall.py inspect udp             # parse & analyze a synthetic UDP packet
  python firewall.py inspect icmp            # parse & analyze a synthetic ICMP packet
  python firewall.py test <proto> <port>     # run a test packet through the rule engine
  python firewall.py rules                    # show loaded rules
  python firewall.py check <proto> <direction> <port>   # check a rule decision
  python firewall.py block <proto> <port>    # print backend command to block
  python firewall.py allow <proto> <port>    # print backend command to allow
  python firewall.py status                  # print backend command to show rules
"""

from __future__ import annotations

import argparse
import os
import sys

# allow running from the project root or directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pfmodules import (  # noqa: E402
    allow_rule_command,
    analyze_packet,
    block_rule_command,
    demo_packet,
    list_connections,
    load_rules,
    platform,
    status_command,
)


def cmd_monitor(args) -> int:
    try:
        lines = list_connections(kind=args.kind or "inet")
    except ImportError:
        print("psutil is required for live monitoring: pip install psutil")
        return 2
    if not lines:
        print("No active connections found (or no permission to enumerate).")
        return 0
    print(f"{'PROTO':<5} {'DIR':<5} {'LOCAL':<22} {'REMOTE':<28} PID")
    print("-" * 62)
    for line in lines:
        print(line)
    return 0


def cmd_inspect(args) -> int:
    data = demo_packet({"tcp": 6, "udp": 17, "icmp": 1}.get(args.proto, 0))
    analysis = analyze_packet(data)
    print(_fmt_analysis(analysis))
    return 0


def cmd_test(args) -> int:
    # Build a demo packet of the requested proto targeting the given dest port.
    import struct
    import socket

    proto_code = {"tcp": 6, "udp": 17, "icmp": 1}[args.proto]
    data = demo_packet(proto_code)
    if args.port:
        # rewrite destination port in the synthetic packet
        base = bytearray(data)
        off = 20  # after IP header
        if proto_code == 6:
            struct.pack_into("!H", base, off + 2, args.port)
        elif proto_code == 17:
            struct.pack_into("!H", base, off + 2, args.port)
        data = bytes(base)
    analysis = analyze_packet(data)
    print(_fmt_analysis(analysis))
    print("--- decision ---")
    decision, matched = evaluate_packet(args.rules, data)
    print(f"Rule engine decision: {decision.upper()}"
          + (f"   (matched {matched.id})" if matched else "   (default)"))
    return 0


def cmd_rules(args) -> int:
    for r in args.rules:
        print(_fmt_rule(r))
    return 0


def cmd_check(args) -> int:
    from pfmodules import evaluate
    decision, matched = evaluate(args.rules, args.direction, args.proto, "", args.port)
    print(f"Decision for {args.proto}/{args.direction} port {args.port}: {decision.upper()}"
          + (f"  (rule {matched.id})" if matched else "  (default allow)"))
    return 0


def cmd_block(args) -> int:
    print(block_rule_command("in", args.proto, args.port, args.ip or ""))
    print(f"(run as {'Administrator' if platform() == 'windows' else 'root'})")
    return 0


def cmd_allow(args) -> int:
    print(allow_rule_command("in", args.proto, args.port, args.ip or ""))
    print(f"(run as {'Administrator' if platform() == 'windows' else 'root'})")
    return 0


def cmd_status(_args) -> int:
    print(status_command())
    return 0


def evaluate_packet(rules, data):
    """Evaluate a raw packet against the rule set (public API in pfmodules)."""
    from pfmodules import evaluate_packet as _eval
    return _eval(rules, data)


def _fmt_rule(r) -> str:
    port = str(r.port) if r.port else "any"
    ip = r.ip if r.ip else "any"
    return f"[{r.action:>5}] {r.direction} {r.proto:>4} port={port:<5} ip={ip}" + (f"  ({r.id})" if r.id else "")


def _fmt_analysis(a) -> str:
    ip = a["ip"]
    lines = [
        f"IP version={ip['version']} ttl={ip['ttl']} proto={ip['protocol_name']} "
        f"{ip['src_ip']} -> {ip['dst_ip']}",
    ]
    t = a["transport"]
    if "tcp" in t:
        tc = t["tcp"]
        lines.append(f"TCP {tc['src_port']} -> {tc['dst_port']} ({tc['service']}) "
                     f"flags={tc['flags_human']} seq={tc['seq']}")
    if "udp" in t:
        ud = t["udp"]
        lines.append(f"UDP {ud['src_port']} -> {ud['dst_port']} ({ud['service']}) len={ud['length']}")
    if "icmp" in t:
        ic = t["icmp"]
        lines.append(f"ICMP type={ic['type']} code={ic['code']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="firewall", description="Personal Firewall (master)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # every subcommand receives the rules list as an attribute for convenience
    def _inject(parser):
        parser.set_defaults(rules=load_rules())

    m = sub.add_parser("monitor", help="list active connections")
    m.add_argument("--kind", default="inet", choices=["inet", "tcp", "udp"])
    _inject(m); m.set_defaults(fn=cmd_monitor)

    i = sub.add_parser("inspect", help="analyze a synthetic packet")
    i.add_argument("proto", choices=["tcp", "udp", "icmp"])
    _inject(i); i.set_defaults(fn=cmd_inspect)

    t = sub.add_parser("test", help="run a packet through the rule engine")
    t.add_argument("proto", choices=["tcp", "udp", "icmp"])
    t.add_argument("port", type=int, nargs="?", default=0)
    _inject(t); t.set_defaults(fn=cmd_test)

    r = sub.add_parser("rules", help="show loaded rules")
    r.set_defaults(rules=load_rules(), fn=cmd_rules)

    c = sub.add_parser("check", help="evaluate a rule decision")
    c.add_argument("proto", choices=["tcp", "udp", "icmp"])
    c.add_argument("direction", choices=["in", "out"])
    c.add_argument("port", type=int, nargs="?", default=0)
    _inject(c); c.set_defaults(fn=cmd_check)

    b = sub.add_parser("block", help="print backend command to block traffic")
    b.add_argument("proto", choices=["tcp", "udp", "icmp"])
    b.add_argument("port", type=int, nargs="?", default=0)
    b.add_argument("--ip", default="")
    _inject(b); b.set_defaults(fn=cmd_block)

    a = sub.add_parser("allow", help="print backend command to allow traffic")
    a.add_argument("proto", choices=["tcp", "udp", "icmp"])
    a.add_argument("port", type=int, nargs="?", default=0)
    a.add_argument("--ip", default="")
    _inject(a); a.set_defaults(fn=cmd_allow)

    s = sub.add_parser("status", help="print backend status command")
    s.set_defaults(fn=cmd_status)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())