# Architecture

## Current Setup
- Windows 11 Pro VM (WIN11-CLIENT01), monitored endpoint running Sysmon
  (SwiftOnSecurity config) and the Splunk Universal Forwarder
- Ubuntu Server VM (splunk-siem), centralized Splunk Enterprise SIEM
- Kali Linux VM, attacker machine, fully integrated into the lab network

All three VMs run on VMware Workstation, NAT networking, on the same
private subnet (192.168.89.0/24).

## Data Flow
Sysmon (Windows endpoint) captures endpoint activity -> Splunk
Universal Forwarder ships logs over port 9997 -> Splunk Enterprise
indexer (Ubuntu VM) ingests and indexes the data -> searchable and
alertable in the Splunk web UI, including scheduled saved searches that
generate logged alert events when detection logic matches.

## Detection Architecture
Each detection follows the same pattern: a scheduled Splunk search
(SPL) runs on an interval, checking a matching time window, and fires a
Log Event trigger action when its condition is met, producing a
searchable alert record with the relevant fields from the triggering
event. See [Investigations_Write_Ups.md](../Investigations_Write_Ups.md)
for the full reasoning behind each detection's logic and known
limitations.

## Roadmap
- [x] Windows endpoint + Sysmon
- [x] Splunk SIEM + Universal Forwarder
- [x] Kali attack VM integrated into network
- [x] Detection engineering (SPL searches mapped to MITRE ATT&CK)
- [x] Documented attack scenarios + investigation writeups
- [ ] Additional MITRE ATT&CK tactic coverage (Defense Evasion, Lateral
      Movement)
- [ ] Visual architecture diagram
- [ ] Real-time (continuously running) alerting for higher-priority
      detections, reducing the scheduled-check detection gap identified
      in Investigation 02
