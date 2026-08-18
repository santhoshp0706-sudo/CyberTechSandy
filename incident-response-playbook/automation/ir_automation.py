"""
IR Automation Toolkit
======================

Lightweight SOAR-style helpers for incident response, built for the
Incident Response Playbook internship project.

Features:
  - Parse Splunk-style alert JSON into a normalized Incident object
  - Auto-classify severity from an alert
  - Map an alert type to its playbook
  - Enrich IOCs (hash/IP/domain) with a mock threat-intel lookup
  - Render an action checklist for the matched playbook
  - Export an incident to the Markdown report template

The SIEM backend is *mocked* so this runs with zero credentials. To use a real
Splunk instance, replace `MockSplunk` with calls to the Splunk REST/HEC API
(see SOCConfig.splunk_* fields).

Usage:
  python ir_automation.py ingest --file alert.json
  python ir_automation.py triage --type ransomware --host WIN-123 --ip 1.2.3.4
  python ir_automation.py enrich --ioc 1.2.3.4 --kind ip
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
class SOCConfig:
    """Connection settings. Mocked by default; fill in for production."""

    splunk_hec_url: str = "https://splunk.example.com:8088/services/collector"
    splunk_hec_token: str = "<<SET_ME>>"
    splunk_rest_url: str = "https://splunk.example.com:8089"
    edr_isolate_api: str = "https://edr.example.com/api/v1/hosts/{id}/isolate"
    use_mock: bool = True  # flip to False to hit real endpoints


# --------------------------------------------------------------------------
# Domain model
# --------------------------------------------------------------------------
class Severity(str, Enum):
    SEV1 = "SEV-1"
    SEV2 = "SEV-2"
    SEV3 = "SEV-3"
    SEV4 = "SEV-4"


PLAYBOOK_MAP = {
    "phishing": ("playbooks/phishing.md", Severity.SEV2),
    "malware": ("playbooks/malware.md", Severity.SEV2),
    "ddos": ("playbooks/ddos.md", Severity.SEV2),
    "data_breach": ("playbooks/data_breach.md", Severity.SEV1),
    "ransomware": ("playbooks/ransomware.md", Severity.SEV1),
    "unauthorized_access": ("playbooks/unauthorized_access.md", Severity.SEV2),
}


@dataclass
class Incident:
    incident_id: str
    alert_type: str
    severity: Severity
    detected_at: str
    host: str | None = None
    src_ip: str | None = None
    user: str | None = None
    description: str = ""
    iocs: list[str] = field(default_factory=list)
    playbook: str | None = None
    actions: list[str] = field(default_factory=list)
    status: str = "OPEN"

    def to_markdown(self) -> str:
        lines = [
            f"# Incident {self.incident_id}",
            "",
            f"- **Severity:** {self.severity.value}",
            f"- **Type:** {self.alert_type}",
            f"- **Detected:** {self.detected_at}",
            f"- **Status:** {self.status}",
            f"- **Host:** {self.host or 'N/A'}",
            f"- **Source IP:** {self.src_ip or 'N/A'}",
            f"- **User:** {self.user or 'N/A'}",
            f"- **Playbook:** {self.playbook or 'N/A'}",
            "",
            "## IOCs",
        ]
        lines += [f"- {ioc}" for ioc in self.iocs] or ["- (none)"]
        lines += ["", "## Immediate Actions"]
        lines += [f"- [ ] {a}" for a in self.actions] or ["- (none)"]
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def new_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"INC-{ts}"


def classify(alert_type: str, raw_severity: str | None = None) -> Severity:
    if raw_severity and raw_severity.upper() in Severity._value2member_map_:
        return Severity(raw_severity.upper())
    return PLAYBOOK_MAP.get(alert_type.lower(), ("", Severity.SEV3))[1]


def build_actions(alert_type: str) -> list[str]:
    """Pull containment actions relevant to the type (subset of playbooks)."""
    common = [
        "Open war-room channel #ir-warroom",
        "Notify Incident Commander",
        "Record timeline with timestamps + actor",
    ]
    specifics = {
        "phishing": ["Quarantine email from all mailboxes", "Reset + revoke sessions if credential submitted", "Block URL/domain at proxy"],
        "malware": ["Isolate host via EDR", "Block hash + C2 at EDR/proxy", "Collect forensic snapshot"],
        "ddos": ["Engage CDN/ISP scrubbing", "Apply edge rate-limiting/ACLs", "Blackhole abusive ranges if safe"],
        "data_breach": ["Block egress to destination", "Revoke account/token", "Engage Legal for notification"],
        "ransomware": ["Isolate host(s) immediately", "Block C2 + hash", "Prepare offline backup restore"],
        "unauthorized_access": ["Disable account + revoke sessions", "Block source IP at conditional access", "Review privilege changes"],
    }
    return common + specifics.get(alert_type.lower(), [])


def enrich_ioc(ioc: str, kind: str) -> dict[str, Any]:
    """Mock threat-intel enrichment. Swap for VirusTotal/MISP/AbuseIPDB in prod."""
    if SOCConfig.use_mock:
        verdict = "malicious" if kind in ("ip", "domain", "hash") and ioc.startswith(("1.", "evil", "dead")) else "unknown"
        return {"ioc": ioc, "kind": kind, "verdict": verdict, "source": "mock-ti"}
    # Real call would go here, e.g. requests.get(f"{ti_url}/ip/{ioc}", ...)
    raise NotImplementedError("Set SOCConfig.use_mock=False and implement real TI lookup")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_triage(args) -> Incident:
    inc = Incident(
        incident_id=new_id(),
        alert_type=args.type,
        severity=classify(args.type, args.severity),
        detected_at=datetime.now(timezone.utc).isoformat(),
        host=args.host,
        src_ip=args.ip,
        user=args.user,
        playbook=PLAYBOOK_MAP.get(args.type.lower(), ("", ""))[0] or None,
    )
    inc.actions = build_actions(args.type)
    if args.ip:
        inc.iocs.append(args.ip)
        res = enrich_ioc(args.ip, "ip")
        print(f"[enrich] {args.ip} -> {res['verdict']} ({res['source']})")
    print(f"[triage] Created {inc.incident_id} | {inc.severity.value} | playbook: {inc.playbook}")
    return inc


def cmd_ingest(args) -> Incident:
    data = json.loads(Path(args.file).read_text())
    atype = data.get("alert_type", "unknown")
    inc = Incident(
        incident_id=data.get("incident_id", new_id()),
        alert_type=atype,
        severity=classify(atype, data.get("severity")),
        detected_at=data.get("detected_at", datetime.now(timezone.utc).isoformat()),
        host=data.get("host"),
        src_ip=data.get("src_ip"),
        user=data.get("user"),
        description=data.get("description", ""),
        iocs=data.get("iocs", []),
        playbook=PLAYBOOK_MAP.get(atype.lower(), ("", ""))[0] or None,
    )
    inc.actions = build_actions(atype)
    print(f"[ingest] Loaded {inc.incident_id} | {inc.severity.value}")
    return inc


def cmd_enrich(args):
    print(json.dumps(enrich_ioc(args.ioc, args.kind), indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="IR Automation Toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("triage", help="Triage a live alert from CLI args")
    t.add_argument("--type", required=True, help="alert type (ransomware, phishing, ...)")
    t.add_argument("--severity", help="override severity SEV-1..4")
    t.add_argument("--host")
    t.add_argument("--ip")
    t.add_argument("--user")
    t.set_defaults(func=cmd_triage)

    i = sub.add_parser("ingest", help="Ingest a Splunk alert JSON file")
    i.add_argument("--file", required=True)
    i.set_defaults(func=cmd_ingest)

    e = sub.add_parser("enrich", help="Enrich a single IOC")
    e.add_argument("--ioc", required=True)
    e.add_argument("--kind", required=True, choices=["ip", "domain", "hash", "url"])
    e.set_defaults(func=cmd_enrich)
    return p


REPO_ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    result = args.func(args)
    if isinstance(result, Incident):
        out_dir = REPO_ROOT / "templates"
        out_dir.mkdir(exist_ok=True)
        out = out_dir / f"{result.incident_id}.md"
        out.write_text(result.to_markdown())
        print(f"[export] Wrote incident report -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
