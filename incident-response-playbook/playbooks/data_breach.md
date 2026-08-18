# Playbook: Data Breach / Exfiltration

**Severity trigger:** SEV-1 (confirmed exfiltration of sensitive data)
**MITRE ATT&CK:** T1041 Exfiltration Over C2, T1567 Exfil Over Web Service

## 1. Detection
- Splunk: large outbound transfers, unusual destination, cloud storage API spikes.
- DLP alert, CASB anomaly, or threat-intel hit on egress.

## 2. Triage (0–30 min)
- [ ] Confirm exfil vs. legitimate backup/sync.
- [ ] Identify data type (PII, IP, credentials) and volume.
- [ ] Identify source host/account and destination.

## 3. Containment (short-term)
- [ ] Block egress to attacker destination (proxy/firewall).
- [ ] Disable/revoke the account or token used.
- [ ] Isolate source host(s) via EDR.
- [ ] Suspend the affected cloud app share if applicable.

## 4. Eradication
- [ ] Remove attacker access and persistence.
- [ ] Rotate all exposed secrets/keys.
- [ ] Close the exfil path (misconfigured bucket, open port, token).

## 5. Recovery
- [ ] Inventory exactly what data left and who is impacted.
- [ ] Engage Legal for breach-notification obligations (timelines!).

## 6. Post-Incident
- [ ] Add IOCs; tune DLP/CASB policies.
- [ ] Notify regulators/customers per legal guidance.
