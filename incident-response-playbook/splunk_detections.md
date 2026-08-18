# Splunk Detection Queries (SPL)

Ready-to-use Splunk Processing Language (SPL) searches mapped to each playbook.
Adjust index/sourcetype names to match your environment. Each query is designed to
run as a **saved search / correlation alert** feeding the SOAR pipeline.

> Replace `index=*` placeholders with your real indexes (e.g., `index=wineventlog`,
> `index=webproxy`, `index=edr`, `index=azuread`).

---

## 1. Phishing — reported email + risky sign-in
```spl
index=email ("reported-phishing" OR subject="*Action Required*")
| stats count by sender, src_user, subject
| join src_user [
    search index=azuread "sign-in activity" riskScore>50
    | stats latest(_time) as risky_login by user
]
```

## 2. Malware — LOLBin / suspicious child process
```spl
index=edr EventType=ProcessCreate
| where like(CommandLine,"%powershell%") AND like(CommandLine,"%-enc%")
| stats count by Hostname, User, CommandLine
| where count > 5
```

## 3. DDoS — volumetric inbound spike (baseline deviation)
```spl
index=firewall action=allowed
| bin _time span=1m
| stats sum(bytes) as bytes by _time, dest_ip
| eventstats avg(bytes) as avg stdev(bytes) as sd by dest_ip
| where bytes > avg + (3*sd)
```

## 4. Data Breach — large outbound transfer
```spl
index=webproxy (category=CloudStorage OR dest_port=443)
| bin _time span=5m
| stats sum(bytes_out) as out by _time, src_user, dest_host
| where out > 500000000
```

## 5. Ransomware — mass file rename + shadow copy delete
```spl
index=edr (EventName="FileRenamed" OR CommandLine="*vssadmin*delete*")
| bin _time span=1m
| stats dc(file_path) as files, values(CommandLine) as cmd by Hostname, _time
| where files > 200
```

## 6. Unauthorized Access — impossible travel / brute force
```spl
index=azuread (status="failure" OR riskScore>70)
| stats count as fails, dc(src_ip) as ips by user
| where fails > 10 OR ips > 3
```
```spl
index=azuread user=* city=* 
| sort user _time
| streamstats current=f window=2 earliest(geo) as prev_geo by user
| where geo!=prev_geo AND duration<2h
```

---

## Alert → SOAR mapping
| Saved search | Severity | Playbook | Automation action |
|--------------|----------|----------|-------------------|
| Phishing-Reported | SEV-3/2 | phishing.md | Quarantine email, reset acct |
| Malware-LOLBin | SEV-2 | malware.md | Isolate host via EDR API |
| DDoS-Volumetric | SEV-2/1 | ddos.md | Page net-ops, enable shield |
| Exfil-LargeOut | SEV-1 | data_breach.md | Block egress, disable token |
| Ransom-MassRename | SEV-1 | ransomware.md | Isolate host, block C2 |
| Access-BruteForce | SEV-2 | unauthorized_access.md | Disable acct, block IP |
