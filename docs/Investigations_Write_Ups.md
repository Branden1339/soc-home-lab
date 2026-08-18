**Investigation 01: Network Service Discovery (RDP Scan)**
**Alert / Trigger**

Splunk saved search/alert: "RDP Inbound Connection Detected" Search: index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389 Initiated=false Triggered by Sysmon Event ID 3 (Network Connection) events on 07/27/2026, ~06:24 PM, sourced from WinEventLog:Microsoft-Windows- Sysmon/Operational on host WIN11-CLIENT01.

**Summary**

An internal host (192.168.89.128) performed a broad TCP port scan against 192.168.89.129, discovering an open RDP service (port 3389). Sysmon logged the resulting inbound connection to the RDP port, which triggered the saved alert.

**Investigation**
Reviewed the triggering event. Sysmon Event ID 3 showed an inbound connection (Initiated: false) from 192.168.89.128 to 192.168.89.129 on port 3389, handled by svchost.exe under the NT AUTHORITY\NETWORK SERVICE account — consistent with the normal process that hosts the RDP service on Windows.
Classified the source IP. 192.168.89.128 is internal to the lab network (192.168.89.0/24), not an external/internet-based address. An internal source changes the investigative framing: rather than asking "is this a random internet scanner," the relevant question becomes "is this a known, expected internal device, or does its presence suggest something already has a foothold on the internal network?"
Checked what was actually scanned. The originating tool (Nmap, -sV scan) probed Nmap's default 1000 most common TCP ports, not port 3389 specifically. This indicates broad reconnaissance behavior — the actor was mapping the host's exposed attack surface generally, rather than specifically hunting for RDP. RDP being open was a discovery, not a targeted probe.
Confirmed the connection reached a real service. A prior scan against the same host, before RDP was enabled, returned all ports "filtered" with no corresponding Sysmon activity — confirming that Sysmon only logs connections that actually reach a listening process, not ones dropped by the firewall. This scan's success in generating a logged event confirms RDP was genuinely reachable and accepting connections at the network level.
**Assessment**

Benign / lab test activity. In this case, the source (192.168.89.128) is a known internal device (an intentionally provisioned Kali VM used for lab testing), and the activity was deliberately generated as part of a controlled exercise. In a real environment, this same finding would warrant escalation rather than automatic dismissal — an internal host performing broad port scans is a legitimate indicator of either compromised-host reconnaissance (lateral movement staging) or an unauthorized/unmanaged device on the network, and would need to be traced back to a known asset owner before being closed out as benign.

**MITRE ATT&CK Mapping**

T1046 - Network Service Discovery (Discovery tactic). The broad, multi-port nature of the scan (rather than a single targeted probe) is what specifically maps this to Network Service Discovery rather than a more targeted technique — the actor was enumerating available services generally, and RDP happened to be one of the results.

**Recommended Action**
Identify and confirm the asset owner/purpose of the source device
If the source is unrecognized or unauthorized, isolate it from the network pending further investigation
Confirm whether RDP exposure on the target host is intentional and necessary; if not, disable it to reduce attack surface
Continue monitoring the source IP for follow-on activity (e.g. login attempts, additional scanning) that would indicate progression beyond reconnaissance
Detection Notes
What made this detectable: Sysmon's Event ID 3 logging combined with a Splunk search filtering for inbound (Initiated=false) connections to a sensitive port (3389). Detection depended on RDP actually being open — a fully firewalled host would have generated no host-based log data for this scan at all (see Day 5 journal entry).
Evasion considerations: A slower, more deliberate scan (e.g. one port at a time, spread over hours, or using timing options to evade common thresholds) would still generate individual Event ID 3 records but would be far less likely to stand out as an obvious burst of activity. This detection currently fires on any single inbound RDP connection — it does not by itself distinguish a scan from a single legitimate remote login, which leads to the next detection layer (see Investigation 02, RDP Brute Force).
False positive potential: Legitimate remote administration, helpdesk RDP sessions, or authorized vulnerability scanning tools would also trigger this exact alert. In a real deployment, this detection would benefit from an allowlist of known admin source IPs to reduce noise.
