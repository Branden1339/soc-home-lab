# SOC Home Lab

A self-built Security Operations Center home lab simulating a small
monitored network: an attacker machine, a Windows endpoint, and a
centralized SIEM. Built from scratch on VMware Workstation, this project
documents the full lifecycle of a SOC environment, endpoint hardening
and logging, SIEM ingestion, live attack simulation, detection
engineering, and formal incident investigation writeups.

## Why this project

Built as hands-on preparation for an entry-level Security Analyst role,
following completion of the Google Cybersecurity Certificate. The goal
was to go beyond certification material and actually build, break,
attack, detect, and document a working environment the way a real SOC
analyst would.

## Architecture

Three-VM lab on VMware Workstation (NAT networking):

| VM | Role | OS |
|---|---|---|
| WIN11-CLIENT01 | Monitored endpoint (Sysmon + Splunk Universal Forwarder) | Windows 11 Pro |
| splunk-siem | Centralized SIEM (Splunk Enterprise) | Ubuntu Server |
| Kali | Attacker machine | Kali Linux |

**Data flow:** Sysmon (endpoint) -> Splunk Universal Forwarder -> port
9997 -> Splunk Enterprise indexer -> searchable/alertable in the Splunk
web UI.

See [docs/Architecture/Roadmap.md](docs/Architecture/Roadmap.md) for
the detailed architecture writeup and project roadmap.

## What's been built

- **Endpoint logging:** Sysmon deployed with the SwiftOnSecurity
  community config for tuned, high-signal event logging
- **Centralized SIEM:** Splunk Enterprise ingesting endpoint logs via
  Universal Forwarder, with custom saved searches and alerts
- **Live attack simulation:** four distinct attack scenarios run from
  Kali against the Windows endpoint, covering four separate MITRE
  ATT&CK tactics
- **Detection engineering:** four custom Splunk detections built from
  scratch, ranging from single-event matching to statistical
  aggregation and Sysmon rule-tag-based detection
- **Formal investigation writeups:** each scenario documented as a full
  incident investigation, including MITRE ATT&CK mapping, severity
  assessment, detection limitations, and evasion considerations, not
  just "it worked"

## Attack scenarios and detections

| # | Scenario | MITRE ATT&CK | Detection Logic |
|---|---|---|---|
| 01 | Nmap port scan (reconnaissance) | T1046 - Network Service Discovery | Single-event match on inbound RDP connection |
| 02 | RDP brute-force login attempt | T1110.001 - Brute Force: Password Guessing | Statistical aggregation, connection count per source IP over time |
| 03 | Encoded PowerShell execution | T1059.001 - PowerShell / T1027 - Obfuscated Files | Command-line substring match for encoding flag |
| 04 | Registry Run key persistence | T1547.001 - Registry Run Keys | Match on Sysmon's own built-in rule tag (RuleName) |

Full writeups for each: [docs/Investigations_Write_Ups.md](docs/Investigations_Write_Ups.md)

## Documentation

- [Lab-Journal.md](docs/Lab-Journal.md), day-by-day build log, including
  real troubleshooting (VM corruption/rebuild, permission issues,
  network misconfigurations) and how each was diagnosed and resolved
- [Investigations_Write_Ups.md](docs/Investigations_Write_Ups.md), full
  incident-style investigation reports for each attack scenario
- [Log-Field-Reference.md](docs/Log-Field-Reference.md), a field-by-field
  breakdown of the Sysmon event types used in this project
- [configs/](configs), the actual Sysmon config and Splunk forwarder
  input configuration used in the lab
- [detections/](detections), the SPL search logic behind each of the
  four detections above

## Skills demonstrated

Windows endpoint security and hardening - Sysmon deployment and tuning -
Splunk SIEM administration (installation, forwarding/receiving, saved
searches, scheduled alerts) - SPL (Search Processing Language),
including field filtering, wildcard matching, and statistical
aggregation - Linux system administration (Ubuntu, LVM disk management,
SSH) - Attack simulation (Nmap, Hydra, ncrack) - PowerShell - MITRE
ATT&CK mapping and threat classification - Incident investigation and
documentation - VMware Workstation lab architecture and networking

## Current Progress

- [x] VMware lab environment (3 VMs, NAT networking)
- [x] Windows 11 endpoint with Sysmon
- [x] Splunk SIEM with Universal Forwarder
- [x] Kali attacker VM integrated into the network
- [x] Four attack scenarios simulated across four MITRE ATT&CK tactics
- [x] Four custom Splunk detections (saved searches + scheduled alerts)
- [x] Four formal investigation writeups
- [ ] Additional detection coverage (Defense Evasion, Lateral Movement)
- [ ] Architecture diagram (visual)

## Repo structure

```
soc-home-lab/
├── README.md
├── configs/                 Sysmon config, forwarder inputs.conf
├── detections/               SPL search logic for each detection
├── docs/
│   ├── Architecture/Roadmap.md
│   ├── Lab-Journal.md
│   ├── Investigations_Write_Ups.md
│   └── Log-Field-Reference.md
```
