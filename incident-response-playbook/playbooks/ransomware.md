# Playbook: Ransomware

**Severity trigger:** SEV-1 (encryption observed or C2 + mass file change)
**MITRE ATT&CK:** T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery

## 1. Detection
- Splunk: mass file-renames, shadow-copy deletion, ransom note drops, C2 beacon.
- EDR: high file-write rate from a single process.

## 2. Triage (0–15 min)
- [ ] Confirm ransomware (note + extensions + encryption behavior).
- [ ] Identify patient-zero host and detonation time.
- [ ] Check for precursor activity (Credential Access, Discovery).

## 3. Containment (short-term) — ACT FAST
- [ ] **Isolate patient-zero and any spreading hosts via EDR immediately.**
- [ ] Disable VLAN/segment access if spreading via SMB.
- [ ] Block C2 IP/domain and the ransomware hash everywhere.
- [ ] Disable compromised accounts; revoke tickets.

## 4. Eradication
- [ ] Do NOT pay the ransom (policy). Collect samples for forensics.
- [ ] Remove persistence and attacker access.
- [ ] Identify initial vector (phishing, RDP, vuln) and remediate.

## 5. Recovery
- [ ] Restore from **offline/immutable backups** (verify integrity first).
- [ ] Rebuild (do not "unlock") affected systems.
- [ ] Enhanced monitoring + password resets org-wide if warranted.

## 6. Post-Incident
- [ ] Test/validate backup restore process.
- [ ] Add IOCs; harden RDP, EDR coverage, and backup isolation.
