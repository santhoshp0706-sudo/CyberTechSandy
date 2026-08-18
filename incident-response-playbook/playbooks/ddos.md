# Playbook: DDoS Attack

**Severity trigger:** SEV-2 (service degraded) / SEV-1 (service down)
**MITRE ATT&CK:** T1498 Network Denial of Service

## 1. Detection
- Splunk: spike in inbound connections/pps, 4xx/5xx rates, upstream ISP alert.
- External monitoring / uptime checks show latency or outage.

## 2. Triage (0–15 min)
- [ ] Confirm it is a DDoS (traffic pattern) vs. outage (single component failure).
- [ ] Identify attack type: volumetric, protocol, application-layer.
- [ ] Identify targeted IP/URL/service.

## 3. Containment (short-term)
- [ ] Engage ISP / CDN / scrubbing provider; enable mitigation (e.g., Cloudflare/AWS Shield).
- [ ] Apply rate-limiting and geo/ACL filters at edge.
- [ ] Blackhole or null-route specific abusive source ranges if safe.

## 4. Eradication
- [ ] Confirm attack traffic subsided; keep mitigations up.
- [ ] Patch/scale the targeted service to absorb load.

## 5. Recovery
- [ ] Gradually relax protections while monitoring.
- [ ] Validate full service availability.

## 6. Post-Incident
- [ ] Document attack vectors and peak bandwidth.
- [ ] Review CDN/ISP SLA and auto-mitigation thresholds.
