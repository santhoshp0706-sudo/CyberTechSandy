# Personal Firewall (Master)

A custom personal firewall application that **monitors** and **filters**
incoming/outgoing traffic, with built-in packet and **protocol analysis**.

**Tools:** Python, `iptables` (Linux), `netsh`/WinAPI (Windows)
**Skills demonstrated:** Network security, packet filtering, protocol analysis

---

## Features

- **Connection monitor** — lists live TCP/UDP connections (via `psutil`).
- **Rule engine** — allow/block decisions on protocol, direction, IP, port.
- **Protocol analysis** — parses raw IP / TCP / UDP / ICMP headers and maps
  well-known ports to service names, decodes TCP flags.
- **OS backends** — generates the exact `iptables` (Linux) or `netsh` (Windows)
  command to enforce a filter.
- **Zero-elevation demo mode** — analyze synthetic packets & test the rule
  engine without root/Administrator rights.
- **JSON rules file** — `rules/rules.json` is fully editable.

---

## Project structure

```
personal-firewall/
├── firewall.py              # main CLI
├── pfmodules/
│   ├── protocol.py          # packet & protocol analysis (IP/TCP/UDP/ICMP)
│   ├── rules.py             # rule engine (load + evaluate)
│   ├── monitor.py           # live connection monitoring
│   ├── backend.py           # iptables / netsh command generation
│   └── __init__.py          # package public API
├── rules/rules.json         # default rules
├── requirements.txt         # optional: psutil for monitor
└── README.md
```

---

## Requirements

- **Python 3.8+**
- Optional (only for `monitor`): `pip install psutil`

---

## How to run

```bash
# 1. Clone the repo and enter the firewall folder
git clone https://github.com/santhoshp0706-sudo/CyberTechSandy.git
cd CyberTechSandy/personal-firewall
pip install -r requirements.txt   # optional: needed for 'monitor'

# 2. Show help
python firewall.py --help
```

---

## Commands

| Command | Purpose |
|---------|---------|
| `python firewall.py monitor` | List active connections |
| `python firewall.py inspect tcp` | Parse & analyze a TCP packet |
| `python firewall.py inspect udp` | Parse & analyze a UDP packet |
| `python firewall.py inspect icmp` | Parse & analyze an ICMP packet |
| `python firewall.py test tcp 22` | Run a packet through the rule engine |
| `python firewall.py rules` | Show loaded rules |
| `python firewall.py check tcp in 3389` | Evaluate a rule decision |
| `python firewall.py block tcp 445` | Print backend command to block |
| `python firewall.py allow udp 53` | Print backend command to allow |
| `python firewall.py status` | Print backend status command |

---

## Examples

**Inspect a packet (protocol analysis):**
```bash
python firewall.py inspect tcp
```
```
IP version=4 ttl=64 proto=TCP 192.168.1.10 -> 8.8.8.8
TCP 49152 -> 443 (HTTPS) flags=ACK+SYN seq=1000
```

**Run a packet through the rule engine:**
```bash
python firewall.py test icmp
```
```
IP version=4 ttl=64 proto=ICMP 192.168.1.10 -> 8.8.8.8
ICMP type=8 code=0
--- decision ---
Rule engine decision: ALLOW   (matched r1)
```

**Check a rule decision:**
```bash
python firewall.py check tcp in 23     # BLOCK (telnet)
python firewall.py check tcp in 443    # ALLOW (default allow)
```

**Generate the blocking command (Windows):**
```bash
python firewall.py block tcp 3389
```
```
netsh advfirewall firewall add rule name="PFW-Block-in-tcp-3389" dir=in \
  action=block protocol=tcp remoteip=any localport=3389
(run as Administrator)
```

**Monitor live connections:**
```bash
python firewall.py monitor
```
```
PROTO DIR   LOCAL                 REMOTE                        PID
TCP   out   192.168.1.10:56012    8.8.8.8:443                   1234
```

---

## Default rules (`rules/rules.json`)

| Action | Direction | Proto | Port | Purpose |
|--------|-----------|-------|------|---------|
| allow  | in        | icmp  | any  | Allow ping |
| block  | in        | tcp   | 23   | Block telnet |
| block  | in        | tcp   | 3389 | Block RDP |
| block  | in        | udp   | 69   | Block TFTP |

Rules are evaluated in order; the first match wins, otherwise traffic is
**allowed** by default.

---

## Notes

- The backend commands are **printed, not executed**, so you never lock
  yourself out accidentally. Run them in a terminal with **root** (Linux) or
  **Administrator** (Windows) privileges.
- Packet inspection uses a **synthetic demo packet** so it works on any OS
  without superuser rights. Point `analyze_packet()` at real captured bytes
  (e.g., from a `SOCK_RAW` socket or scapy) to analyze live traffic.