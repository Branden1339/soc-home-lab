**Investigation 01: Network Service Discovery (RDP Scan)**
**Alert / Trigger**

Splunk saved search/alert: "RDP Inbound Connection Detected" Search: index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389 Initiated=false Triggered by Sysmon Event ID 3 (Network Connection) events on 07/27/2026, ~06:24 PM, sourced from WinEventLog:Microsoft-Windows- Sysmon/Operational on host WIN11-CLIENT01.

**Summary**

An internal host (192.168.89.128) performed a broad TCP port scan against 192.168.89.129, discovering an open RDP service (port 3389). Sysmon logged the resulting inbound connection to the RDP port, which triggered the saved alert.

**Investigation**
Reviewed the triggering event. Sysmon Event ID 3 showed an inbound connection (Initiated: false) from 192.168.89.128 to 192.168.89.129 on port 3389, handled by svchost.exe under the NT AUTHORITY\NETWORK SERVICE account — consistent with the normal process that hosts the RDP service on Windows.
Classified the source IP. 192.168.89.128 is internal to the lab network (192.168.89.0/24), not an external/internet-based address. An internal source changes the investigative framing: rather than asking "is this a random internet scanner," the relevant question becomes "is this a known, expected internal device, or does its presence suggest something already has a foothold on the internal network?"
Checked what was actually scanned. The originating tool (Nmap, -sV scan) probed Nmap's default 1000 most common TCP ports, not port 3389 specifically. This indicates broad reconnaissance behavior. The actor was mapping the host's exposed attack surface generally, rather than specifically hunting for RDP. RDP being open was a discovery, not a targeted probe.
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

**Investigation 02: RDP Brute Force Attempt**
**Alert / Trigger**

Splunk saved search/alert: "RDP Brute Force Attempt Detected" Search: index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389 Initiated=false | stats count by SourceIp | where count > 5 Triggered by an aggregation of Sysmon Event ID 3 (Network Connection) events on 08/17/2026, ~09:00-09:15 PM, sourced from WinEventLog:Microsoft-Windows-Sysmon/Operational on host WIN11-CLIENT01. Scheduled to run hourly, checking the last 60 minutes.

**Summary**

An internal host (192.168.89.128) made repeated RDP connection attempts against 192.168.89.129 over roughly 15 minutes, using a brute-force tool (ncrack) attempting a fixed username against a list of passwords. Sysmon logged 71 individual connection attempts at regular ~20 second intervals; the aggregation-based alert correctly identified the source IP as exceeding the 5-connection threshold within the hour.

**Investigation**
Reviewed the raw Sysmon Event ID 3 records. Unlike the single connection event seen in the earlier reconnaissance finding (Investigation 01), this activity showed dozens of near-identical connection events from the same source IP to the same destination port, spaced at regular ~20 second intervals over an extended period.
Identified the pattern as the key indicator. A single RDP connection to port 3389 has an innocent explanation (a normal login). Repeated connections to the same port, from the same source, at consistent intervals, only make sense as an automated process guessing credentials — a human manually re-entering a password wrong would not produce this regular a rhythm. This regularity is what elevates the finding from "a connection happened" to "a credential-guessing attempt is in progress."
Classified the source and target. As with Investigation 01, the source (192.168.89.128) is internal to the lab network. Whereas the first finding was about what was exposed, this finding is about an actor actively trying to use that exposure to gain access — a meaningfully more advanced and more dangerous stage of an attack.
Checked for corresponding Windows Security log activity (Event ID 4625, failed logon). No matching events were found. Investigation determined this was because most connection attempts timed out during the RDP TLS/NLA handshake before a full logon attempt was ever completed — meaning Windows' own authentication layer never had a "failed password" event to record, even though Sysmon clearly captured the network-level connection attempts. This is an important finding in its own right: relying on Event ID 4625 alone would have missed this activity entirely.
Confirmed the attack did not succeed. No valid credentials were found; the brute-force tool (ncrack) halted on its own after "too many failed attempts," consistent with some form of connection throttling or rate-limiting behavior on the RDP service pushing back against the rapid repeated attempts.
Evaluated the detection timing. The attack itself completed in roughly 15 minutes (71 probes). The alert is scheduled to run hourly, checking the prior 60 minutes. This means the alert did correctly catch the activity, but in the worst case an attack of this nature could run to completion up to ~59 minutes before the next scheduled check even looks at the data — a real detection gap, independent of whether the search logic itself is correct.
**Assessment**

Unsuccessful attack, but not a non-event. No credentials were compromised and the source is a known internal test device in this case, but the finding demonstrates two things worth flagging even in a "failed" scenario: (1) the target's RDP service was reachable and subjected to a real credential-guessing attempt, meaning it is a live, attractive target regardless of this specific attempt's outcome, and (2) the detection pipeline correctly identified the pattern, but with a meaningful delay built into its current scheduling. In a real environment with an unrecognized source IP, this would be treated as a credential access attempt requiring immediate escalation, not just logged and closed.

**MITRE ATT&CK Mapping**

T1110.001 - Brute Force: Password Guessing (Credential Access tactic). This is specifically Password Guessing rather than Password Spraying (T1110.003) because a single, fixed username was targeted against multiple passwords — Password Spraying would instead involve one or a few passwords tried against many different usernames, a different technique aimed at avoiding per-account lockout thresholds.

**Recommended Action**
Identify and confirm the asset owner of the source device; if unrecognized, isolate immediately given the credential-access nature of the activity
Verify whether the targeted account has any indication of successful authentication around the time of the attempts (cross-check successful logon events, not just failed ones)
Reduce the alert's scheduled interval from hourly to a shorter window (e.g. every 5-15 minutes) to reduce the detection gap; a real-time or continuously-running search would close this gap further, at the cost of additional system resource usage — a reasonable tradeoff to evaluate based on environment size and Splunk indexer capacity
Consider enabling or verifying account lockout policy on the target, as an additional layer of defense independent of detection
Investigate whether RDP needs to be exposed to this source/network segment at all; reducing exposure is a stronger control than detection alone
**Detection Notes**
What made this detectable: the aggregation logic (stats count by SourceIp | where count > 5) specifically looks for volume from a single source, which is what actually distinguishes a brute-force attempt from an isolated legitimate connection. The earlier single-event detection (Investigation 01) would have fired on the very first connection attempt here too, but would not by itself have conveyed that this was a sustained, repeated attack rather than one connection.
Detection gap identified: the hourly schedule creates up to a ~59 minute window in which a complete brute-force attempt could run and finish before the next scheduled check. The detection logic itself is sound; the scheduling interval is the weaker link.
Evasion considerations: an attacker using a lower request rate (e.g. one attempt every few minutes instead of every 20 seconds) could stay under the count > 5 per-hour threshold while still eventually succeeding through sheer persistence over a longer timeframe — a "low and slow" brute force would likely evade this specific detection as configured.
False positive potential: a legitimate user repeatedly mistyping their own password, or a misconfigured application retrying a stored (outdated) credential automatically, could both trigger this alert. Correlating with the account name involved (once available) and checking for eventual successful authentication would help distinguish genuine attacks from these benign causes.
