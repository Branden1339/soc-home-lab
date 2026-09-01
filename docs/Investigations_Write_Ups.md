# Investigation 01: Network Service Discovery (RDP Scan)

## Alert / Trigger
Splunk saved search/alert: **"RDP Inbound Connection Detected"**
Search: `index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389
Initiated=false`
Triggered by Sysmon Event ID 3 (Network Connection) events on
07/27/2026, ~06:24 PM, sourced from `WinEventLog:Microsoft-Windows-
Sysmon/Operational` on host WIN11-CLIENT01.

## Summary
An internal host (192.168.89.128) performed a broad TCP port scan
against 192.168.89.129, discovering an open RDP service (port 3389).
Sysmon logged the resulting inbound connection to the RDP port, which
triggered the saved alert.

## Investigation
1. **Reviewed the triggering event.** Sysmon Event ID 3 showed an
   inbound connection (`Initiated: false`) from 192.168.89.128 to
   192.168.89.129 on port 3389, handled by `svchost.exe` under the
   `NT AUTHORITY\NETWORK SERVICE` account, consistent with the normal
   process that hosts the RDP service on Windows.
2. **Classified the source IP.** 192.168.89.128 is internal to the lab
   network (192.168.89.0/24), not an external/internet-based address.
   An internal source changes the investigative framing: rather than
   asking "is this a random internet scanner," the relevant question
   becomes "is this a known, expected internal device, or does its
   presence suggest something already has a foothold on the internal
   network?"
3. **Checked what was actually scanned.** The originating tool (Nmap,
   `-sV` scan) probed Nmap's default 1000 most common TCP ports, not
   port 3389 specifically. This indicates broad reconnaissance behavior:
   the actor was mapping the host's exposed attack surface generally,
   rather than specifically hunting for RDP. RDP being open was a
   discovery, not a targeted probe.
4. **Confirmed the connection reached a real service.** A prior scan
   against the same host, before RDP was enabled, returned all ports
   "filtered" with no corresponding Sysmon activity, confirming that
   Sysmon only logs connections that actually reach a listening
   process, not ones dropped by the firewall. This scan's success in
   generating a logged event confirms RDP was genuinely reachable and
   accepting connections at the network level.

## Assessment
**Benign / lab test activity.** In this case, the source
(192.168.89.128) is a known internal device (an intentionally
provisioned Kali VM used for lab testing), and the activity was
deliberately generated as part of a controlled exercise. In a real
environment, this same finding would warrant escalation rather than
automatic dismissal; an internal host performing broad port scans is
a legitimate indicator of either compromised-host reconnaissance
(lateral movement staging) or an unauthorized/unmanaged device on the
network, and would need to be traced back to a known asset owner before
being closed out as benign.

## MITRE ATT&CK Mapping
**T1046 - Network Service Discovery** (Discovery tactic). The broad,
multi-port nature of the scan (rather than a single targeted probe)
is what specifically maps this to Network Service Discovery rather than
a more targeted technique; the actor was enumerating available services
generally, and RDP happened to be one of the results.

## Recommended Action
- Identify and confirm the asset owner/purpose of the source device
- If the source is unrecognized or unauthorized, isolate it from the
  network pending further investigation
- Confirm whether RDP exposure on the target host is intentional and
  necessary; if not, disable it to reduce attack surface
- Continue monitoring the source IP for follow-on activity (e.g. login
  attempts, additional scanning) that would indicate progression beyond
  reconnaissance

## Detection Notes
- **What made this detectable:** Sysmon's Event ID 3 logging combined
  with a Splunk search filtering for inbound (`Initiated=false`)
  connections to a sensitive port (3389). Detection depended on RDP
  actually being open; a fully firewalled host would have generated no
  host-based log data for this scan at all (see Day 5 journal entry).
- **Evasion considerations:** A slower, more deliberate scan (e.g. one
  port at a time, spread over hours, or using timing options to evade
  common thresholds) would still generate individual Event ID 3 records
  but would be far less likely to stand out as an obvious burst of
  activity. This detection currently fires on any single inbound RDP
  connection; it does not by itself distinguish a scan from a single
  legitimate remote login, which leads to the next detection layer
  (see Investigation 02, RDP Brute Force).
- **False positive potential:** Legitimate remote administration,
  helpdesk RDP sessions, or authorized vulnerability scanning tools
  would also trigger this exact alert. In a real deployment, this
  detection would benefit from an allowlist of known admin source IPs
  to reduce noise.



# Investigation 02: RDP Brute Force Attempt

## Alert / Trigger
Splunk saved search/alert: **"RDP Brute Force Attempt Detected"**
Search: `index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389
Initiated=false | stats count by SourceIp | where count > 5`
Triggered by an aggregation of Sysmon Event ID 3 (Network Connection)
events on 08/17/2026, ~09:00-09:15 PM, sourced from
`WinEventLog:Microsoft-Windows-Sysmon/Operational` on host
WIN11-CLIENT01. Scheduled to run hourly, checking the last 60 minutes.

## Summary
An internal host (192.168.89.128) made repeated RDP connection attempts
against 192.168.89.129 over roughly 15 minutes, using a brute-force tool
(ncrack) attempting a fixed username against a list of passwords. Sysmon
logged 71 individual connection attempts at regular ~20 second intervals;
the aggregation-based alert correctly identified the source IP as
exceeding the 5-connection threshold within the hour.

## Investigation
1. **Reviewed the raw Sysmon Event ID 3 records.** Unlike the single
   connection event seen in the earlier reconnaissance finding
   (Investigation 01), this activity showed dozens of near-identical
   connection events from the same source IP to the same destination
   port, spaced at regular ~20 second intervals over an extended period.
2. **Identified the pattern as the key indicator.** A single RDP
   connection to port 3389 has an innocent explanation (a normal login).
   Repeated connections to the *same* port, from the *same* source, at
   consistent intervals, only make sense as an automated process
   guessing credentials; a human manually re-entering a password
   wrong would not produce this regular a rhythm. This regularity is
   what elevates the finding from "a connection happened" to "a
   credential-guessing attempt is in progress."
3. **Classified the source and target.** As with Investigation 01, the
   source (192.168.89.128) is internal to the lab network. Whereas the
   first finding was about *what* was exposed, this finding is about an
   actor actively trying to *use* that exposure to gain access, a
   meaningfully more advanced and more dangerous stage of an attack.
4. **Checked for corresponding Windows Security log activity (Event ID
   4625, failed logon).** No matching events were found. Investigation
   determined this was because most connection attempts timed out
   during the RDP TLS/NLA handshake before a full logon attempt was
   ever completed, meaning Windows' own authentication layer never
   had a "failed password" event to record, even though Sysmon clearly
   captured the network-level connection attempts. This is an important
   finding in its own right: relying on Event ID 4625 alone would have
   missed this activity entirely.
5. **Confirmed the attack did not succeed.** No valid credentials were
   found; the brute-force tool (ncrack) halted on its own after "too
   many failed attempts," consistent with some form of connection
   throttling or rate-limiting behavior on the RDP service pushing back
   against the rapid repeated attempts.
6. **Evaluated the detection timing.** The attack itself completed in
   roughly 15 minutes (71 probes). The alert is scheduled to run
   hourly, checking the prior 60 minutes. This means the alert did
   correctly catch the activity, but in the worst case an attack of
   this nature could run to completion up to ~59 minutes before the
   next scheduled check even looks at the data, a real detection gap,
   independent of whether the search logic itself is correct.

## Assessment
**Unsuccessful attack, but not a non-event.** No credentials were
compromised and the source is a known internal test device in this
case, but the finding demonstrates two things worth flagging even in a
"failed" scenario: (1) the target's RDP service was reachable and
subjected to a real credential-guessing attempt, meaning it is a live,
attractive target regardless of this specific attempt's outcome, and
(2) the detection pipeline correctly identified the pattern, but with a
meaningful delay built into its current scheduling. In a real
environment with an unrecognized source IP, this would be treated as a
credential access attempt requiring immediate escalation, not just
logged and closed.

## MITRE ATT&CK Mapping
**T1110.001 - Brute Force: Password Guessing** (Credential Access
tactic). This is specifically Password Guessing rather than Password
Spraying (T1110.003) because a single, fixed username was targeted
against multiple passwords; Password Spraying would instead involve
one or a few passwords tried against many different usernames, a
different technique aimed at avoiding per-account lockout thresholds.

## Recommended Action
- Identify and confirm the asset owner of the source device; if
  unrecognized, isolate immediately given the credential-access nature
  of the activity
- Verify whether the targeted account has any indication of successful
  authentication around the time of the attempts (cross-check
  successful logon events, not just failed ones)
- Reduce the alert's scheduled interval from hourly to a shorter window
  (e.g. every 5-15 minutes) to reduce the detection gap; a real-time
  or continuously-running search would close this gap further, at the
  cost of additional system resource usage, a reasonable tradeoff to
  evaluate based on environment size and Splunk indexer capacity
- Consider enabling or verifying account lockout policy on the target,
  as an additional layer of defense independent of detection
- Investigate whether RDP needs to be exposed to this source/network
  segment at all; reducing exposure is a stronger control than
  detection alone

## Detection Notes
- **What made this detectable:** the aggregation logic (`stats count by
  SourceIp | where count > 5`) specifically looks for *volume* from a
  single source, which is what actually distinguishes a brute-force
  attempt from an isolated legitimate connection. The earlier
  single-event detection (Investigation 01) would have fired on the
  very first connection attempt here too, but would not by itself have
  conveyed that this was a sustained, repeated attack rather than one
  connection.
- **Detection gap identified:** the hourly schedule creates up to a
  ~59 minute window in which a complete brute-force attempt could run
  and finish before the next scheduled check. The detection logic
  itself is sound; the scheduling interval is the weaker link.
- **Evasion considerations:** an attacker using a lower request rate
  (e.g. one attempt every few minutes instead of every 20 seconds)
  could stay under the `count > 5` per-hour threshold while still
  eventually succeeding through sheer persistence over a longer
  timeframe; a "low and slow" brute force would likely evade this
  specific detection as configured.
- **False positive potential:** a legitimate user repeatedly mistyping
  their own password, or a misconfigured application retrying a stored
  (outdated) credential automatically, could both trigger this alert.
  Correlating with the account name involved (once available) and
  checking for eventual successful authentication would help distinguish
  genuine attacks from these benign causes.


# Investigation 03: Suspicious Encoded PowerShell Execution

## Alert / Trigger
Splunk saved search/alert: **"Suspicious Encoded PowerShell Execution"**
Search: `index=main host="WIN11-CLIENT01" EventCode=1
CommandLine="*EncodedCommand*"`
Triggered by a Sysmon Event ID 1 (Process Create) event on 08/31/2026,
~02:19 PM, sourced from `WinEventLog:Microsoft-Windows-Sysmon/
Operational` on host WIN11-CLIENT01. Scheduled via cron (`*/15 * * * *`)
to run every 15 minutes, checking the last 15 minutes.

## Summary
A `cmd.exe` process on WIN11-CLIENT01 spawned `powershell.exe` using the
`-EncodedCommand` parameter, a base64-encoded command line. This process
chain and command-line pattern is a well-known technique used to obscure
the true intent of a PowerShell command from simple keyword-based
detection.

## Investigation
1. **Reviewed the triggering event.** Sysmon Event ID 1 showed
   `powershell.exe` (Image) launched by `cmd.exe` (ParentImage), running
   under user `WIN11-CLIENT01\brand`, with `IntegrityLevel: Medium`
   (not elevated/administrator). The `CommandLine` field contained
   `-EncodedCommand` followed by a base64-encoded string.
2. **Decoded the command for verification.** The base64 string decoded
   to `Invoke-WebRequest -Uri http://example.com`, a command that
   fetches content from a URL. In this case the destination was a
   benign test domain, but the technique itself (encoded PowerShell
   fetching a remote resource) is structurally identical to how real
   malware stagers and droppers retrieve second-stage payloads.
3. **Assessed why the encoding itself matters, independent of what it
   decodes to.** Base64 encoding does not make a command
   uncrackable; it is trivially reversible by an analyst who knows to
   decode it. Its actual value to an attacker is evading detection
   tools that rely on matching plain-text keywords (e.g. scanning for
   the literal string `Invoke-WebRequest` or `DownloadString`), since an
   encoded command line will not contain those strings verbatim. This
   means the presence of `-EncodedCommand` itself is a meaningful
   indicator, regardless of the decoded content's apparent severity.
4. **Noted an associated Sysmon Event ID 8 (CreateRemoteThread)** logged
   in close proximity to the process creation. CreateRemoteThread is
   associated with process injection techniques and warrants a closer
   look in a full investigation, though it can also occur as a normal
   part of certain application initialization; flagged here as
   something to correlate further rather than a confirmed finding.
5. **Considered how this activity could occur without prior alerts.**
   Unlike the reconnaissance (Investigation 01) and brute-force
   (Investigation 02) findings, this event does not depend on any prior
   network-based attack against the host. A very common real-world path
   to this exact process chain is phishing: a user opens a
   malicious email attachment (e.g. a macro-enabled Office document),
   and the Office application spawns PowerShell directly, with no
   scanning or credential-guessing involved at all. This means an
   Execution-stage detection like this one is necessary independent of
   whether earlier-stage detections (recon, credential access) fired,
   since phishing skips directly to this stage.

## Assessment
**Higher severity than Investigations 01 and 02, and treated as
suspicious pending further review.** The first two findings both
represented an attacker attempting to gain access, which is pre-compromise
activity. This finding represents code already executing on the
endpoint, meaning some form of access (legitimate or otherwise) already
exists. In this lab, the command itself was benign (contacting a test
domain), but the pattern, encoded PowerShell spawned from cmd.exe, is
identical in structure to real malware execution chains and should be
treated as a genuine indicator requiring investigation in any real
environment, not dismissed based on the specific decoded content alone.

## MITRE ATT&CK Mapping
**T1059.001 - Command and Scripting Interpreter: PowerShell**
(Execution tactic). The use of `-EncodedCommand` specifically also maps
to **T1027 - Obfuscated Files or Information** (Defense Evasion tactic),
since the technique's primary purpose is evading detection rather than
enabling any additional functionality the command wouldn't otherwise
have. This event is a good example of a single piece of activity
mapping to more than one ATT&CK technique simultaneously.

## Recommended Action
- Decode and review the full command line content immediately upon
  alert (do not treat "it's encoded" as a stopping point; decoding is
  quick and provides the actual evidence)
- Correlate with the user's recent activity: was this user expected to
  be running PowerShell commands, and does their broader activity
  (email, browser history, other process activity) suggest a phishing
  interaction shortly before this event?
- Investigate the associated CreateRemoteThread event (Event ID 8) to
  rule out or confirm process injection
- If the decoded command references an external URL or IP, check it
  against threat intelligence sources before assuming benign intent
- Consider PowerShell logging/restriction policies (e.g. Constrained
  Language Mode, script block logging) as a preventive control, in
  addition to detection

## Detection Notes
- **What made this detectable:** searching Event ID 1's `CommandLine`
  field for the literal string `-EncodedCommand` using both-sided
  wildcards (`"*EncodedCommand*"`), necessary because the flag appears
  in the middle of the full command line, not at the start or end.
- **Evasion considerations:** an attacker aware of this detection could
  avoid the literal `-EncodedCommand` flag by using PowerShell's
  parameter abbreviation (e.g. `-enc` or even shorter unambiguous
  prefixes PowerShell accepts), which would not match this specific
  search string. A more robust detection would account for common
  abbreviated forms of the flag, or focus on other indicators (e.g. any
  PowerShell process with a very long or high-entropy command line)
  rather than relying on one exact flag spelling.
- **False positive potential:** legitimate IT automation and some
  software installers do use `-EncodedCommand` intentionally (e.g. to
  safely pass complex commands through multiple layers of shell
  parsing). Correlating with the parent process, user, and whether the
  activity fits expected administrative behavior is necessary to
  distinguish this from a genuine attack.

  # Investigation 04: Registry Run Key Persistence

## Alert / Trigger
Splunk saved search/alert: **"Registry Run Key Persistence Detected"**
Search: `index=main host="WIN11-CLIENT01" EventCode=13
RuleName="*RunKey*"`
Triggered by a Sysmon Event ID 13 (Registry Value Set) event on
08/31/2026, ~07:56 PM, sourced from `WinEventLog:Microsoft-Windows-
Sysmon/Operational` on host WIN11-CLIENT01. Scheduled via cron
(`*/15 * * * *`) to run every 15 minutes, checking the last 15 minutes.

## Summary
A `powershell.exe` process wrote a new value named `WindowsUpdateHelper`
into the current user's Run key
(`HKCU\...\CurrentVersion\Run`), pointing at the same encoded PowerShell
command identified in Investigation 03. This configures the command to
launch automatically on every future login, establishing persistence
independent of the original process that created it.

## Investigation
1. **Reviewed the triggering event.** Sysmon Event ID 13 showed
   `powershell.exe` (Image) writing a value to
   `HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\
   WindowsUpdateHelper` (TargetObject), with `Details` containing the
   full command: `powershell.exe -EncodedCommand <base64 blob>`, the
   identical encoded command investigated in Investigation 03.
2. **Confirmed Sysmon's own rule tagging.** The event's `RuleName`
   field read `T1060,RunKey`, meaning the SwiftOnSecurity Sysmon config
   already classifies writes to this registry location as a known
   persistence technique, independent of any custom Splunk search
   logic. This is a stronger detection foundation than pattern-matching
   the registry path manually, since it relies on Sysmon's own
   validated rule rather than a hand-written wildcard match that could
   contain gaps.
3. **Distinguished this event from a related side-effect event.**
   A separate Event ID 13 was also generated by `sihost.exe` writing to
   a `RunNotification` key with the same value name appended, this is
   Windows' own internal startup-notification bookkeeping reacting to
   the Run key change, not a second malicious action. Correctly
   identifying which of the two events represented the actual attacker
   action (the one written by `powershell.exe`, not `sihost.exe`) was a
   necessary step to avoid mis-attributing legitimate Windows behavior
   as a separate finding.
4. **Assessed severity relative to Investigation 03.** In Investigation
   03, the malicious action was a single, one-time process execution;
   terminating that process would have fully removed the threat.
   Here, the malicious action is no longer tied to any single running
   process at all, the registry value itself is the threat, and it will
   independently relaunch the encoded command on every future login
   until it is explicitly removed. This decouples the attack from any
   process-level remediation, a meaningfully different and more
   dangerous situation than a one-time execution.
5. **Considered remediation order.** Before removing the malicious
   registry value, the full value name, path, and payload content
   should be documented (exported or screenshotted) as evidence.
   Deleting it immediately upon discovery, without first capturing this
   detail, would remove the ability to fully document the incident,
   share exact indicators with other teams, or build detections for the
   same specific value elsewhere in the environment.

## Assessment
**More severe than Investigation 03, and requires remediation beyond
process termination.** This finding represents an attacker (or, in this
lab, a simulated equivalent) taking a deliberate step to survive a
reboot or the loss of their current session, rather than a one-time
action. In a real environment, this would be treated as a confirmed
persistence mechanism requiring both the registry value's removal and a
broader check for other persistence locations the same actor may have
also used (scheduled tasks, services, other Run key variants, startup
folder items), since an attacker who plants one persistence mechanism
frequently plants more than one as a backup.

## MITRE ATT&CK Mapping
**T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys /
Startup Folder** (Persistence tactic). Sysmon's own config tags this
with the older technique ID (T1060), which has since been reorganized
under the current ATT&CK naming (T1547.001); both refer to the same
underlying technique.

## Recommended Action
- Document the full registry value (name, path, and Details/payload
  content) before making any changes, preserving it as evidence
- Remove the malicious Run key entry once documented
- Check for additional persistence mechanisms on the same host
  (Scheduled Tasks, services, HKLM Run key, Startup folder) rather than
  assuming this was the only one planted
- Terminate any currently running process matching the payload, though
  note this alone is insufficient remediation given the registry entry
  survives independently
- Isolate the host from the network pending full investigation, since
  confirmed persistence indicates a higher likelihood of a genuine,
  ongoing compromise rather than a passing/opportunistic event
- Review login history for the affected account around and after the
  time the entry was created, to determine whether the persistence
  mechanism has already triggered on a subsequent login

## Detection Notes
- **What made this detectable:** searching Event ID 13 for Sysmon's own
  `RuleName` field tag (`*RunKey*`) rather than manually pattern-matching
  the registry path. This is more reliable than a custom path-based
  search, since it depends on Sysmon's maintained detection logic rather
  than a hand-written wildcard pattern that could contain gaps or typos.
- **Evasion considerations:** an attacker could use a different, less
  commonly monitored persistence location that Sysmon's default rule
  set does not tag with a RuleName (for example, certain scheduled task
  configurations or less common registry autostart locations), which
  would not trigger this specific detection even though it accomplishes
  the same persistence goal. A defense-in-depth approach combining
  RuleName-based detection with broader TargetObject path matching
  across multiple known persistence locations would reduce this gap.
- **False positive potential:** many legitimate applications
  (communication tools, update utilities, antivirus software) also
  write to the Run key as part of normal installation. The `Details`
  field content is what actually distinguishes a legitimate entry (a
  normal installed application path) from a malicious one (an encoded
  or obfuscated command); this alert should not be treated as
  automatically malicious without reviewing that field.
