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
- Default Sysmon logging without a config is extremely noisy — using a
  community-vetted config (SwiftOnSecurity) tunes what gets logged
- Event ID 1 (Process Create) is the most important event type for
  investigations — it captures process name, PID, ProcessGuid, and (in the
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
  actually forwarding the logs you want — the input config (inputs.conf)
  has to explicitly point it at the right log/channel
- Sysmon's Operational log channel has a locked-down access list tighter
  than standard Windows logs, so the forwarder's default service account
  couldn't read it without being changed to Local System
- Troubleshooting a log pipeline effectively means checking each layer
  independently: network connectivity, forwarder registration, channel
  permissions, then indexing/search — rather than treating "no results" as
  one unsolvable problem

### Next Steps
Explore Sysmon data in Splunk (build basic searches around Event ID 1),
then move toward setting up the Kali attack VM to start generating traffic
for detection engineering.
