# Playbook: Phishing Incident

**Severity trigger:** SEV-2 (credential submitted) / SEV-3 (reported, no interaction)
**MITRE ATT&CK:** T1566 Phishing, T1078 Valid Accounts

## 1. Detection
- Splunk: employee-reported phishing via report-button (see `splunk_detections.md`).
- SIEM: impossible-travel or new-IP login shortly after report.

## 2. Triage (0–30 min)
- [ ] Confirm the email is malicious (sender, links, attachments, headers).
- [ ] Identify all recipients (mail gateway log search).
- [ ] Determine if any link was clicked / credential submitted.

## 3. Containment (short-term)
- [ ] Quarantine the email from all mailboxes (mail gateway / M365 Security).
- [ ] If credential submitted: **disable account + force password reset + revoke sessions**.
- [ ] Block malicious URL/domain at proxy and EDR.
- [ ] If attachment opened: treat host as per Malware playbook (isolate via EDR).

## 4. Eradication
- [ ] Remove inbox rules / forwarding the attacker may have set.
- [ ] Purge residual邮件 from quarantine.
- [ ] Reset MFA if compromised; review MFA enrollments for the account.

## 5. Recovery
- [ ] Monitor account for 14 days (sign-in logs, forwarding rules).
- [ ] Notify users of the campaign; reinforce report-button usage.

## 6. Post-Incident
- [ ] Add URL/domain/sender to blocklist & detection logic.
- [ ] Update phishing awareness training examples.
