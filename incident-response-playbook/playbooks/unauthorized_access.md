# Playbook: Unauthorized Access / Account Compromise

**Severity trigger:** SEV-2 (confirmed adversary use of valid account)
**MITRE ATT&CK:** T1078 Valid Accounts, T1110 Brute Force, T1550 Pass-the-Ticket

## 1. Detection
- Splunk: brute-force spikes, impossible travel, new-ASN sign-ins, MFA fatigue.
- Privileged account use outside baseline.

## 2. Triage (0–30 min)
- [ ] Distinguish attack from legitimate but odd login.
- [ ] Identify account, source IP, time, and actions taken.
- [ ] Check whether privilege escalation occurred.

## 3. Containment (short-term)
- [ ] Disable account / revoke active sessions and refresh tokens.
- [ ] Force MFA re-enrollment; block source IP/ASN at conditional access.
- [ ] If privileged: isolate related hosts and review admin actions.

## 4. Eradication
- [ ] Reset credentials; review and remove unauthorized changes (Groups, GPO, ACLs).
- [ ] Kill any attacker-created persistence (new accounts, backdoors).
- [ ] Patch the access vector (exposed service, weak MFA).

## 5. Recovery
- [ ] Re-enable account only after cleanup + monitoring enabled.
- [ ] 14-day sign-in watch.

## 6. Post-Incident
- [ ] Tighten conditional access / MFA policies.
- [ ] Add detections for the observed TTPs.
