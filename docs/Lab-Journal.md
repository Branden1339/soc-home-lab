# SOC Home Lab Journal

## Day 1

### Objective
Build the Windows endpoint.

### Completed

- Installed Windows 11
- Installed VMware Tools
- Updated Windows
- Created baseline snapshot

### Lessons Learned

- VMware snapshots make it easy to roll back changes.
- VMware Tools improves VM performance and usability.

### Next Steps

Install Sysmon.

## Day 2

### Objective
Install and configure Sysmon on the Windows 11 endpoint.

### Completed
- Downloaded Sysmon from Microsoft Sysinternals
- Downloaded SwiftOnSecurity's community Sysmon config (sysmonconfig-export.xml)
- Installed Sysmon with the config via elevated PowerShell:
  `.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml`
- Verified service is running (`Get-Service sysmon64`)
- Confirmed logging in Event Viewer under
  Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

### Lessons Learned
- Sysmon requires an elevated (Administrator) PowerShell/cmd session to install,
  since it installs a kernel driver + service
- Default Sysmon logging without a config is extremely noisy, using a
  community-vetted config (SwiftOnSecurity) tunes what gets logged
- Event ID 1 (Process Create) is the most important event type for
  investigations, it captures process name, PID, ProcessGuid, and (in the
  Details tab) command line and parent process

### Next Steps
Install Splunk (SIEM) and Universal Forwarder to ship these Sysmon logs off
the endpoint for centralized search and analysis.

## Day 3

### Objective
Stand up Splunk Enterprise as a centralized SIEM and forward Sysmon logs
from the Windows 11 endpoint to it.

### Completed
- Created a dedicated Ubuntu Server VM (Splunk-SIEM) as a separate machine
  from the Windows endpoint, on NAT networking
- Installed OpenSSH during setup and confirmed remote access via SSH from host
- Downloaded and installed Splunk Enterprise (.deb) on the Ubuntu VM
- Started Splunk (`--accept-license --run-as-root`), confirmed web UI
  accessible at http://<VM-IP>:8000
- Enabled "Receive data" on port 9997 in Splunk (Settings > Forwarding and
  receiving)
- Downloaded and installed Splunk Universal Forwarder (on-prem, not cloud)
  on the Windows 11 VM, pointed at the Splunk server's IP on port 9997
- Verified network-level connection with `ss -tnp | grep 9997` (ESTAB)
- Fixed a low disk space issue blocking Splunk search/indexing by extending
  the LVM logical volume and filesystem (`lvextend` + `resize2fs`) to use
  free space already in the volume group
- Created inputs.conf on the forwarder to monitor the Sysmon Operational
  event log channel
- Diagnosed and fixed errorCode=5 (Access Denied) when the forwarder tried
  to subscribe to the Sysmon channel, by changing the SplunkForwarder
  service to run as Local System instead of its default NT SERVICE account
- Confirmed Sysmon events are now flowing end-to-end and searchable in
  Splunk (`index=main host="WIN11-CLIENT01"`)

### Lessons Learned
- Ubuntu's installer uses LVM by default, which can leave unallocated space
  in the volume group even if the virtual disk was sized larger
- Splunk pauses search/indexing below a minimum free disk threshold (default
  5000MB) as a safety mechanism, not a sign the pipeline is broken
- A Universal Forwarder being connected (network-level) does not mean it's
  actually forwarding the logs you want, the input config (inputs.conf)
  has to explicitly point it at the right log/channel
- Sysmon's Operational log channel has a locked-down access list tighter
  than standard Windows logs, so the forwarder's default service account
  couldn't read it without being changed to Local System
- Troubleshooting a log pipeline effectively means checking each layer
  independently: network connectivity, forwarder registration, channel
  permissions, then indexing/search, rather than treating "no results" as
  one unsolvable problem

### Next Steps
Explore Sysmon data in Splunk (build basic searches around Event ID 1),
then move toward setting up the Kali attack VM to start generating traffic
for detection engineering.

## Day 4

### Objective
Bring the Kali Linux VM online as the lab's attacker machine and confirm
network connectivity across all three VMs (Kali, Windows 11, Splunk-SIEM).

### Completed
- Booted existing Kali Linux VM, confirmed default login
- Verified Kali's network adapter is set to NAT, matching the Windows and
  Splunk VMs
- Confirmed Kali's IP (192.168.89.128) is on the same subnet as the
  Windows VM (192.168.89.129) and Splunk VM (192.168.89.131)
- Updated Kali (`apt update && apt upgrade`)
- Diagnosed a one-directional ping failure (Kali -> Windows failed,
  Windows -> Kali worked) as an inbound Windows Firewall block
- Enabled inbound ICMPv4 rules on the Windows VM
  (`Enable-NetFirewallRule -DisplayName "*ICMPv4-In*"`)
- Confirmed full bidirectional ping connectivity between Kali and the
  Windows VM

### Lessons Learned
- DHCP-assigned IPs on a NAT network aren't guaranteed to persist across
  VM reboots, always re-verify current IPs rather than assuming
  yesterday's addresses still apply
- Windows Firewall blocks inbound ICMP (ping) by default as a basic
  hardening measure, to prevent easy host discovery during reconnaissance
- A one-directional ping failure (works one way, not the other) points to
  a block on the target host specifically, not a routing/network issue,
  testing both directions narrows down where a connectivity problem
  actually lives
- VMware can occasionally leave a stale "in use" lock on a VM after an
  interrupted session; powering off all VMs and restarting clears it
  without needing to remove/re-add the VM

### Next Steps
All three VMs (Kali attacker, Windows 11 endpoint, Splunk SIEM) are
confirmed connected. Next: run a first test attack from Kali (e.g. a
port scan) against the Windows VM and confirm Sysmon/Splunk captures the
resulting activity, first step into actual detection engineering.

## Day 5

### Objective
Run a first attack simulation from Kali against the Windows 11 endpoint
and confirm Sysmon/Splunk captures it as a real, analyzable detection.

### Completed
- Ran an initial Nmap scan (`nmap -sV`) from Kali against the Windows VM,
  all 1000 ports came back "filtered" (Windows Firewall silently dropping
  probes), confirming Windows was reachable but exposing no open services
- Checked Splunk for resulting Sysmon Event ID 3 activity, found only
  unrelated OneDrive sync traffic, confirming the filtered scan left
  nothing for Sysmon to observe (packets never reached a process)
- Enabled Remote Desktop (RDP) on the Windows VM:
  - Set `fDenyTSConnections` registry value to 0
  - Enabled the "Remote Desktop" firewall rule group
  - Confirmed the Terminal Services (TermService) service running
- Re-ran the Nmap scan, port 3389/tcp now returned open, identified as
  ms-wbt-server (RDP)
- Searched Splunk (`index=main host="WIN11-CLIENT01" EventCode=3
  DestinationPort=3389`) and found matching Sysmon events capturing the
  scan hitting the RDP port
- Broke down the full event fields (RuleName, Initiated, SourceIp,
  DestinationPort, Image, User) to understand what makes this event a
  legitimate detection vs routine background noise

### Lessons Learned
- A fully firewall-filtered scan generates no host-based log activity,
  Sysmon only sees traffic that actually reaches a process on the
  endpoint, not packets blocked at the network layer
- This is why host-based tools (Sysmon) and network-based tools
  (firewall/IDS logs) complement each other, they observe different
  layers of an attack
- Key fields that turn a raw Sysmon network event into a meaningful
  detection: Initiated (inbound vs outbound), SourceIp (who connected),
  DestinationPort (what service was targeted), and RuleName (Sysmon's own
  config tagging known-significant traffic like RDP)
- RDP (port 3389) is one of the most commonly attacked real-world
  services, heavily tied to ransomware entry, a strong first detection
  scenario to build around

### Next Steps
Build a saved Splunk search (and eventually an alert) around this RDP
connection pattern, the natural next step from "found it manually" to
actual detection engineering.

## Day 6

### Objective
Turn the manually-found RDP detection into an automated Splunk saved
search and alert, and validate the full pipeline end-to-end.

### Completed
- Refined the search to specifically target inbound connections:
  `index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389
  Initiated=false`
- Saved the search as a Report named "RDP Inbound Connection Detected"
- Configured scheduling: runs hourly, checking the last 60 minutes
  (adjusted time range to match the run interval and avoid detection gaps)
- Added a "Log Event" trigger action that writes a searchable alert
  event whenever the search finds a match, using field values from the
  triggering event ($result.SourceIp$, $result.DestinationIp$,
  $result.DestinationPort$)
- Diagnosed an Nmap "0 hosts up" false negative, the inbound ICMP
  firewall rule didn't persist through a VM restart, causing Nmap's
  default host-alive ping check to fail; fixed using the -Pn flag
- Manually triggered the saved search after a fresh scan and confirmed
  the Log Event action fired correctly, producing a searchable alert
  entry with accurate source IP, destination IP, and port

### Lessons Learned
- Some manual firewall changes (like enabling inbound ICMP) don't persist
  across VM reboots, worth remembering to re-check before assuming
  connectivity is still configured the same way
- A scheduled search's time range should match its run frequency to avoid
  gaps where activity could be missed between checks
- Nmap's default ping check can produce a false "host is down" result
  even when the target is fully reachable but not responding to ICMP,
  -Pn bypasses this
- Running multiple VMs simultaneously on a 16GB host requires deliberately
  right-sizing memory per VM (Windows 4GB, Splunk 4GB, Kali 2GB) rather
  than using defaults everywhere
- Completed the full loop from manual detection to automated alerting:
  detection -> scheduled search -> trigger condition -> logged action,
  which is genuinely explainable end-to-end in an interview setting

### Next Steps
Expand detection coverage to other MITRE ATT&CK-relevant scenarios beyond
RDP scanning (e.g. brute-force login attempts, SMB enumeration, or
suspicious process creation chains), and continue building out the
Log-Field-Reference.md and Concept-Notes.md docs as new event types come up.

## Day 7

### Objective
Recover from Windows 11 VM corruption caused by a OneDrive file deletion,
and restore the lab to full working order.

### Completed
- Discovered the Windows 11 VM (WIN11-SOC) could not power on after
  deleting files from OneDrive, VMware reported missing .vmdk files
- Attempted recovery: checked OneDrive's recycle bin, verified files were
  actually still present locally, moved the VM folder out of OneDrive to
  a local path, and worked backward through the full VMware snapshot
  chain (Day 5 -> Day 4 -> Sysmon+Forwarder -> Sysmon Installed ->
  01-Clean Windows), every restore point failed with the same
  "parent of this virtual disk could not be opened" error, confirming
  the base disk itself was corrupted, not just a snapshot
- Decided to rebuild the Windows 11 VM from scratch rather than continue
  chasing the corruption
- Created the new VM directly under C:\VMs\WIN11-SOC (local disk, no
  OneDrive) to prevent this from happening again
- Windows 11 Pro fresh install (required for RDP support), VMware Tools,
  Windows Update, baseline snapshot
- Reinstalled Sysmon with the SwiftOnSecurity config (had to redo the
  download twice due to incomplete zip/file downloads along the way)
- Reinstalled the Splunk Universal Forwarder, set the service to run as
  Local System from the start this time (already knew this fix from Day 3)
- Diagnosed a "no stanzas found" forwarder error caused by inputs.conf
  appearing to save in Notepad but actually remaining empty on disk;
  fixed by explicitly re-saving and verifying with Get-Content before
  restarting the service
- Discovered the new VM's hostname defaulted to WIN11-SOC instead of
  WIN11-CLIENT01, which explained why searches were returning no
  results even though data was flowing; renamed the computer back to
  WIN11-CLIENT01 to match existing documentation and saved searches
- Re-enabled RDP, then diagnosed why port 3389 stayed filtered despite
  every individual setting (registry, firewall rule, service status)
  looking correct:
  - Found the network adapter had been auto-classified as "Public"
    profile, which scopes Windows' built-in RDP firewall rules to not
    apply; reclassified to "Private" to match the lab's actual trust
    level
  - Even after that, RDP still wasn't listening on 3389, found two
    RDP-dependent services (SessionEnv, UmRdpService) were stopped
    despite TermService itself showing "Running"
  - Starting those services didn't fully resolve it either; a full
    VM restart was ultimately required to get the RDP stack to bind
    to the port correctly
- Confirmed full pipeline restored end-to-end: Nmap scan from Kali finds
  port 3389 open, Sysmon logs the connection, Splunk shows the event,
  and the Day 6 "RDP Inbound Connection Detected" alert fires correctly

### Lessons Learned
- OneDrive sync and VM storage should never mix, even after fixing this
  once before, files can still get deleted/corrupted if a VM folder is
  anywhere OneDrive touches; VMs now live under C:\VMs, fully outside any
  synced folder
- A working snapshot chain doesn't protect against base disk corruption,
  if the very first snapshot fails to open, the underlying disk itself
  is damaged, not the snapshot layering
- New Windows installs don't automatically retain hostname, network
  profile classification, or service states from a previous machine,
  every one of those needs to be re-verified after a rebuild, not
  assumed to carry over
- "Service shows Running" doesn't guarantee a feature is fully
  functional, RDP required three separate services (TermService,
  SessionEnv, UmRdpService) working together, and checking the port
  directly (Get-NetTCPConnection) was more reliable than trusting
  service status alone
- Network profile (Public vs Private) silently scopes which firewall
  rules apply, even when those rules show "Enabled: True", a rule
  can be on and still not apply on the current profile
- When multiple system-level changes stack up in one session (rename,
  network profile change, service state changes), a full restart is
  sometimes the fastest real fix, even after individually verifying
  each piece looks correct

### Next Steps
Snapshot the rebuilt VM now that it's fully verified working. Resume
building out additional attack scenarios (starting with an RDP
brute-force attempt using Hydra) on top of this restored environment.

## Day 8

### Objective
Simulate an RDP brute-force attack from Kali and build a second, distinct
Splunk detection that identifies the attack pattern (volume/frequency)
rather than a single connection event.

### Completed
- Created a small custom wordlist for controlled brute-force testing
  instead of using the full rockyou.txt list
- Attempted the brute-force with Hydra's RDP module, consistently failed
  to establish a connection; used xfreerdp to confirm RDP itself was
  fully reachable and functional, isolating the issue to Hydra's RDP
  module specifically (which its own output flags as "experimental")
- Along the way, disabled Network Level Authentication (NLA) on the
  Windows VM to rule it out as a compatibility blocker (temporary lab
  change, not a real-world recommendation)
- Switched to ncrack, which has more reliable RDP support; worked through
  a transient "No route to host" network error that resolved on its own,
  then tuned ncrack's timing options (CL=1, at=1, cd=3s) to avoid
  timeouts against RDP's inherently slow TLS/NLA handshake per attempt
- Successfully ran a real brute-force attempt against the Windows VM's
  RDP service; ncrack stopped itself early due to "too many failed
  attempts," suggesting some form of built-in rate-limiting/lockout
  behavior
- Found in Splunk that the existing Day 6 "RDP Inbound Connection
  Detected" alert correctly fired during this test, confirming it still
  works after the VM rebuild
- Checked for Windows Security Event ID 4625 (failed logon) and found
  nothing, determined this was because most connection attempts timed
  out during the TLS/NLA handshake before ever reaching the point of a
  real logon attempt, so Windows never had a "failed login" to record
- Observed the raw Sysmon Event ID 3 data: dozens of connections from the
  same source IP at regular ~20 second intervals, a clearly different
  pattern from a single scan-triggered event
- Built a second, more advanced detection using SPL aggregation:
  `index=main host="WIN11-CLIENT01" EventCode=3 DestinationPort=3389
  Initiated=false | stats count by SourceIp | where count > 5`
- Saved this as a new Alert ("RDP Brute Force Attempt Detected"),
  scheduled hourly, with a Log Event action reporting the source IP and
  attempt count

### Lessons Learned
- Not all attacker tools are equally reliable, Hydra's RDP module is
  explicitly experimental and failed consistently, while switching tools
  (ncrack) solved the same task; knowing multiple tools for the same
  technique is a real, useful skill
- A single inbound connection and a burst of repeated connections from
  the same source require different detection logic, a raw event match
  (Day 6's detection) catches the former, but an aggregation with `stats
  count by` and a `where` threshold is needed to catch the latter
  (volume-based) pattern
- Different Windows/Sysmon log sources capture different stages of an
  attack: Sysmon Event ID 3 shows the network connection attempt itself,
  while Windows Security Event ID 4625 shows a completed failed login,
  an attack can generate one without the other depending on how far it
  actually progressed
- RDP brute-forcing is genuinely slow in the real world due to per-attempt
  TLS/NLA overhead, which is part of why account lockout policies and
  connection throttling are effective real-world defenses against it

### Next Steps
Continue expanding the detection library with additional MITRE
ATT&CK-mapped scenarios (e.g. SMB enumeration, suspicious process
creation chains). Consider writing up one or two of these scenarios as
a full investigation-style report for the portfolio, walking through
detection -> investigation -> conclusion the way a real SOC analyst
would document a finding.

## Day 9

### Objective
Build two additional attack scenarios (Execution via encoded PowerShell,
Persistence via a registry Run key), write both up as formal
investigations, and clean up the GitHub repo for presentation.

### Completed
- Simulated a suspicious execution chain: cmd.exe spawning powershell.exe
  with an -EncodedCommand flag (base64-encoded Invoke-WebRequest),
  representing the kind of process chain seen in phishing-driven
  malicious macro attacks
- Confirmed the resulting Sysmon Event ID 1 event captured the full
  parent-child relationship, command line, integrity level, and hashes;
  noted an associated Event ID 8 (CreateRemoteThread) worth correlating
  further in a full investigation
- Built and saved a third detection ("Suspicious Encoded PowerShell
  Execution") searching Event ID 1 CommandLine for the -EncodedCommand
  substring, using both-sided wildcards; scheduled via cron every 15
  minutes based on the detection-gap lesson from Investigation 02
- Documented Investigation 03, including the dual MITRE ATT&CK mapping
  (T1059.001 Execution and T1027 Defense Evasion for the same event) and
  why encoding evades keyword-based detection without making the
  command truly unreadable
- Simulated a persistence mechanism: reused the same encoded PowerShell
  command from Investigation 03 as the payload for a new registry Run
  key entry (HKCU...CurrentVersion\Run), tying the two scenarios into
  one connected attack narrative
- Found that Sysmon's own SwiftOnSecurity config already tags Run key
  writes via the RuleName field (T1060/RunKey), and built the fourth
  detection around that field instead of hand-matching the registry
  path, for more reliable detection than custom pattern-matching
- Correctly distinguished the actual malicious registry write
  (powershell.exe) from a Windows-internal side-effect event
  (sihost.exe writing to a RunNotification key) that appeared in the
  same search results
- Documented Investigation 04, including why persistence is more severe
  than a one-time execution (the threat survives process termination),
  and the "document before remediate" principle for evidence handling
- Cleaned up the GitHub repo: rewrote README.md to reflect the actual
  completed state of the project, rewrote the Architecture Roadmap doc

### Lessons Learned
- Persistence and one-time execution require fundamentally different
  remediation: killing a process is sufficient for the latter, but
  insufficient for the former, since a persistence mechanism survives
  independently of any running process
- Sysmon's own rule tagging (RuleName field) is a more reliable
  detection foundation than hand-written path or keyword matching,
  since it is validated by the community config rather than subject to
  the same wildcard/typo risks as a custom search
- Side-effect events (like Windows' own internal notification logging)
  can appear alongside the real malicious event in the same search
  results; correctly identifying which event represents the actual
  attacker action, rather than a system's automatic reaction to it, is
  a necessary investigative step
- Reusing a payload across scenarios (the same encoded PowerShell
  command from Execution, now used for Persistence) produces a more
  coherent portfolio narrative than unconnected, one-off demonstrations

### Next Steps
Repo is now presentation-ready with four complete scenarios, four
detections, and four investigation writeups spanning Discovery,
Credential Access, Execution/Defense Evasion, and Persistence. Possible
future additions: Defense Evasion or Lateral Movement scenarios, a
visual architecture diagram, and moving toward real-time (rather than
scheduled) alerting for the higher-priority detections.
