# SOC Home Lab: Attack Simulation & Threat Detection with Splunk

A self-built Security Operations Center lab simulating a multi-stage attack chain — reconnaissance, payload execution, command-and-control, and persistence — with detections engineered in Splunk using Sysmon telemetry, and a response procedure documented against NIST SP 800-61.

> Resume/portfolio project name: **Splunk Incident Response Lab & Threat Triage Sandbox**

---

## Project Overview

This lab was built to practice the core workflow of a SOC Analyst L1: get telemetry flowing, generate realistic adversary activity, detect it with SPL, and document the response. Rather than presenting a sanitized "everything worked" writeup, this repo documents the real build process — including the configuration issues and dead ends encountered — because that troubleshooting is itself part of the skill being demonstrated.

**What this lab covers:**
- Isolated 2-VM network build with static IP addressing
- Sysmon + Splunk Enterprise telemetry pipeline (no forwarder — single-host direct ingestion)
- Simulated network reconnaissance (Nmap)
- Simulated payload delivery, execution, and C2 callback (Metasploit/msfvenom)
- Simulated persistence via Windows Registry Run key
- SPL detections for each stage, correlated into a single attack-chain timeline
- An Incident Response Playbook mapped to NIST SP 800-61's four phases

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│              VMware LAN Segment (192.168.10.0/24)                     │
│                    Isolated – no internet egress                      │
│                                                                       │
│   ┌──────────────────────┐                 ┌──────────────────────┐   │
│   │     Kali Linux       │                 │      Windows 10      │   │
│   │      Attacker        │   attacks       │        Victim        │   │
│   │                      │ ──────────────► │                      │   │
│   │ IP: 192.168.10.33    │                 │ IP: 192.168.10.34    │   │
│   │                      │                 │                      │   │
│   │ • Nmap               │                 │ • Sysmon             │   │
│   │ • Metasploit         │                 │ • Splunk Enterprise  │   │
│   │                      │                 │                      │   │
│   └──────────────────────┘                 └──────────┬───────────┘   │
│                                                       │               │
│                                                       ▼               │
│                                             ┌──────────────────────┐  │
│                                             │   Sysmon Telemetry   │  │
│                                             │          ↓           │  │
│                                             │  Splunk Local Index  │  │
│                                             └──────────┬───────────┘  │
│                                                        │              │
│                                                        ▼              │
│                                             ┌──────────────────────┐  │
│                                             │   SPL Detections     │  │
│                                             │                      │  │
│                                             │ • C2                 │  │
│                                             │ • Persistence        │  │
│                                             └──────────────────────┘  │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

```
*(Diagram also available as an image in `/diagrams/architecture.png`)*

---

## Tech stack

| Component | Purpose |
|---|---|
| VMware Workstation (LAN Segment) | Isolated, host-only virtual network |
| Kali Linux | Attacker platform — Nmap, Hydra, Metasploit/msfvenom |
| Windows 10 | Victim host |
| Sysmon (SwiftOnSecurity config) | Endpoint telemetry — process, network, registry events |
| Splunk Enterprise | SIEM — ingestion, SPL detections, dashboards |
| NIST SP 800-61 | Incident response framework used for the playbook |

---

## Attack chain simulated

1. **Reconnaissance** — `nmap -sS -sV -O` and `--script vuln` against the victim
2. **Execution** — Meterpreter reverse-TCP payload (`msfvenom`) delivered and run on the victim
3. **Command & Control** — persistent callback session to the attacker host
4. **Persistence** — Windows Registry Run key added for reboot survival

Mapped to MITRE ATT&CK: T1595 (Active Scanning), T1204 (User Execution), T1071 (Application Layer Protocol), T1547.001 (Registry Run Keys).

---

## Repository structure

```
├── README.md                        ← you are here
└── docs/
    ├── 01-setup.md                  ← LAN segment, static IPs, Sysmon/Splunk install
    ├── 02-data-validation.md        ← confirming telemetry ingestion
    ├── 03-network-scanning.md       ← Nmap recon + detection notes
    ├── 04-malware-execution.md      ← payload delivery & execution
    ├── 05-c2-beacon.md              ← C2 callback + SPL detection
    ├── 06-registry-persistence.md   ← persistence mechanism + SPL detection
    ├── 07-attack-chain-correlation.md ← the full correlated timeline
    └── 08-ir-playbook.md            ← NIST SP 800-61 response playbook
```

Each file in `docs/` follows the same format: **what was done → what broke (if anything) → how it was fixed → SPL query used → result and analysis.**

---

## Key detections (SPL)

**Data validation**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| stats count by EventCode
```

**C2 beacon (regularity/jitter analysis)**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp="<Kali_IP>"
| streamstats current=f last(_time) as last_time by DestinationIp
| eval delta=_time-last_time
| stats avg(delta) as avg_delta, stdev(delta) as stdev_delta, count by DestinationIp
| eval jitter=stdev_delta/avg_delta
```

**Registry persistence**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Run\\*"
| table _time, TargetObject, Details, Image
```

Full query set and explanations: see `/docs/`.

---

## Lessons learned

- Sysmon's default install only logs process create/terminate — network and registry visibility require an explicit config (SwiftOnSecurity ruleset), or C2 and persistence activity go completely undetected.
- A payload/handler mismatch (`generic/shell_reverse_tcp` vs. `windows/x64/meterpreter/reverse_tcp`) silently kills the session instead of erroring clearly — always verify both sides use the identical payload string.
- Windows Firewall silently drops unsolicited scan traffic, meaning Sysmon (which only logs *completed* connections) has no visibility into port scans — firewall drop logging or Security Event ID 5152 auditing is required as a separate detection source.

Full write-up: `/docs/08-ir-playbook.md`

---

## Author

**Tejaswiny** — Final-year B.E. CSE (Cybersecurity), KCG College of Technology, Chennai.
Built as part of ongoing SOC Analyst (L1) portfolio development.
