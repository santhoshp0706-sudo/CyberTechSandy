# Metrics & KPIs

Measure IR program health. Report monthly to the CISO.

## Core SLAs (targets)
| Metric | Definition | Target (SEV-1) | Target (SEV-2) |
|--------|------------|----------------|----------------|
| **MTTD** (Mean Time to Detect) | Alert → validated incident | < 30 min | < 2 hr |
| **MTTA** (Mean Time to Acknowledge) | Detect → responder engaged | 15 min | 30 min |
| **MTTC** (Mean Time to Contain) | Acknowledge → contained | 1 hr | 4 hr |
| **MTTR** (Mean Time to Resolve) | Detect → closed | 24 hr | 7 days |

## Quality Metrics
- **False-positive rate** of SIEM alerts (target < 20%).
- **Playbook adherence** (% incidents following a playbook).
- **Backlog** of open incidents by severity.
- **Detection coverage** (% of MITRE ATT&CK tactics with a detection).
- **Tabletop completion** (exercises run vs planned).

## Reporting cadence
- Weekly: open incidents, SLA breaches.
- Monthly: MTTD/MTTA/MTTC/MTTR trends, FP rate, coverage.
- Quarterly: program review + playbook refresh.

## Continuous improvement loop
```
metrics -> identify gap -> update playbook/detection -> train -> measure again
```
