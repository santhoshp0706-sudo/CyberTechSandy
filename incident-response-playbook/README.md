# Incident Response Playbook

**Internship Project** — Security Operations / Incident Response
**Tools:** Splunk (SIEM), SOAR / response automation tools
**Skills demonstrated:** Incident management, crisis response, SIEM threat detection

---

## Project Overview

This repository is a complete **Incident Response (IR) Plan and Playbook**. It guides a
security team through the full lifecycle of a security breach — from **identification**
through **containment** and **mitigation** — using SIEM tooling and automated response.

It is structured around the industry-standard **NIST SP 800-61r2** incident response
lifecycle and the **SANS PICERL** model, adapted for a small/mid-size SOC.

### What's inside

| Path | Description |
|------|-------------|
| `incident_response_plan.md` | The master IR plan: team, severity model, communication, lifecycle |
| `playbooks/` | Step-by-step response procedures for common incident types |
| `splunk_detections.md` | Ready-to-use Splunk SPL queries to *detect* each incident type |
| `automation/` | Python-based response automation (alert triage, IOC enrichment, case creation) |
| `templates/` | Incident report, IOC tracker, and runbook checklists |
| `metrics.md` | KPIs / SLAs used to measure IR program maturity |

---

## The Incident Response Lifecycle

```
 Preparation ──> Detection & Analysis ──> Containment ──> Eradication
      ^                                                           │
      │                                                           ▼
      └──────────── Post-Incident Activity <── Recovery <─────────┘
```

1. **Preparation** — tooling, runbooks, training, access.
2. **Detection & Analysis** — SIEM alerts, triage, validation, scoping.
3. **Containment** — short-term (stop the bleed) then long-term (isolate).
4. **Eradication** — remove root cause, attacker persistence, IOCs.
5. **Recovery** — restore services, monitor, validate.
6. **Post-Incident** — lessons learned, metrics, process improvement.

---

## How to use this repo

1. Read `incident_response_plan.md` to understand roles and severity.
2. For an active incident, open the matching `playbooks/<type>.md`.
3. Run the corresponding detection in `splunk_detections.md` to validate scope.
4. Use `automation/ir_automation.py` to enrich IOCs and open a case.
5. Record everything in the `templates/` trackers.

---

## Quick start (automation)

```bash
pip install -r automation/requirements.txt
python automation/ir_automation.py --help
```

> **Note:** The automation scripts use a mocked SIEM backend so they run without
> credentials. Point them at a real Splunk HEC / REST endpoint by editing the
> `SOCConfig` block to use them in production.
