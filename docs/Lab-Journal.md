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
