# Architecture

## Current Setup
- Windows 11 VM (WIN11-CLIENT01) — monitored endpoint running Sysmon
- Ubuntu Server VM (splunk-siem) — centralized Splunk Enterprise SIEM
- Kali Linux VM — planned attacker machine (not yet integrated)

## Data Flow
Sysmon (Windows endpoint) -> Splunk Universal Forwarder -> port 9997 ->
Splunk Enterprise indexer (Ubuntu VM) -> searchable in Splunk web UI

## Roadmap
- [x] Windows endpoint + Sysmon
- [x] Splunk SIEM + Universal Forwarder
- [x] Kali attack VM integrated into network
- [ ] Detection engineering (SPL searches mapped to MITRE ATT&CK)
- [ ] Documented attack scenarios + investigation writeups
