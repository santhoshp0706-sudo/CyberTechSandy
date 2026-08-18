# Incident Response Plan

**Version:** 1.0
**Owner:** Security Operations Center (SOC)
**Classification:** Internal — Incident Response
**Aligned to:** NIST SP 800-61r2, SANS PICERL, MITRE ATT&CK

---

## 1. Purpose & Scope

This plan defines how the organization detects, responds to, and recovers from
security incidents. It applies to all IT assets, cloud workloads, endpoints, and
employee accounts.

**Objectives**
- Minimize impact (data loss, downtime, reputational harm).
- Ensure a **consistent, repeatable** response.
- Preserve evidence for forensics and legal.
- Continuously improve via post-incident review.

**Out of scope:** Physical security events, pure HR/policy violations (handled by
separate processes) unless they involve a security breach.

---

## 2. Incident Response Team (CSIRT)

| Role | Responsibility | Named contact |
|------|----------------|---------------|
| **Incident Commander (IC)** | Overall decision authority, declares severity, coordinates | SOC Lead |
| **IR Lead / Triage** | Technical lead, drives containment | Tier-2 Analyst |
| **Threat Hunter / Detection** | SIEM monitoring, Splunk queries, detection engineering | Tier-1/Tier-3 |
| **Forensics** | Evidence collection, memory/disk imaging | DFIR Analyst |
| **Network/Infra Eng** | Implements containment at network/host level | IT Ops |
| **Communications** | Internal/external comms, legal, PR liaison | Comms/Legal |
| **Executive Sponsor** | Business decisions, breach notification authority | CISO |

> **RACI note:** The IC is *Accountable*; IR Lead is *Responsible*; all other roles
> are *Consulted* during their domain actions.

---

## 3. Incident Definitions & Severity Model

An **event** is any observable occurrence. An **incident** is an event that
compromises confidentiality, integrity, or availability.

### Severity levels

| Sev | Name | Examples | Response SLA | Comms |
|-----|------|----------|--------------|-------|
| **SEV-1** | Critical | Confirmed ransomware, active data exfiltration, domain-wide compromise | 15 min ack / 1 hr containment | Exec + Legal immediately |
| **SEV-2** | High | Single-host malware, successful phishing with credential use, DDoS impacting service | 30 min ack / 4 hr containment | Exec within 1 hr |
| **SEV-3** | Medium | Suspicious login, failed intrusion attempt, isolated alert | 2 hr ack / 24 hr | Team lead |
| **SEV-4** | Low | Policy violation, false-positive tuning, informational | 1 business day | Ticket only |

### False positive handling
Every closed "false positive" must record the tuning rule so detection quality
improves over time.

---

## 4. Incident Lifecycle (detailed)

### Phase 1 — Preparation
- SIEM (Splunk) ingest configured for logs: endpoint, firewall, AD, cloud, web proxy.
- Playbooks maintained and reviewed **quarterly**.
- Tabletop exercises at least **twice a year**.
- Pre-approved containment scripts and access (break-glass accounts).

### Phase 2 — Detection & Analysis
- Alerts from Splunk correlation searches / SOAR.
- **Triage questions:** Is it real? What is the scope? What is the impact?
- Validate with detection queries (see `splunk_detections.md`).
- Assign severity, open case, notify IC if SEV-1/2.

### Phase 3 — Containment
- **Short-term:** disable account, block IP, isolate host (EDR), quarantine email.
- **Long-term:** segment network, patch, rotate credentials, deploy ACLs.
- Document every action with timestamp + actor (chain of custody).

### Phase 4 — Eradication
- Remove malware, kill persistence (scheduled tasks, registry, services).
- Identify and close the initial access vector.
- Reset all potentially exposed credentials.

### Phase 5 — Recovery
- Restore from clean backups, rebuild compromised hosts.
- Enhanced monitoring for 2–4 weeks post-incident.
- Verify business functionality before declaring "resolved".

### Phase 6 — Post-Incident Activity
- Lessons-learned meeting within **5 business days**.
- Update playbooks, detections, and metrics.
- Report to stakeholders and regulators if required (e.g., 72-hour breach notice).

---

## 5. Communication Plan

| Audience | Channel | When |
|----------|---------|------|
| IR team | Slack `#ir-warroom` (or Teams) | Immediate on declare |
| Executives | Phone + email | SEV-1/2 immediately |
| Legal / Compliance | Secure email | Before any external notice |
| Affected users | Comms-approved message | As directed by IC |
| Public / Regulators | Approved statement only | Via Comms/Legal only |

**War-room rules:** One channel, one IC, decisions in writing, no speculation.

---

## 6. Legal & Compliance

- Preserve evidence (do not reboot before imaging where possible).
- Document chain of custody.
- Breach notification timelines (e.g., GDPR 72h, state laws vary) tracked by Legal.
- Engage law enforcement per policy for SEV-1.

---

## 7. Reference Documents

- `playbooks/` — scenario procedures
- `splunk_detections.md` — detection content
- `automation/` — SOAR/response scripts
- `templates/incident_report.md` — reporting
- `templates/ioc_tracker.md` — IOC ledger
- `metrics.md` — KPIs & SLAs
