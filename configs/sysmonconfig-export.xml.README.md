# Sysmon Configuration

The Sysmon config used throughout this lab is the SwiftOnSecurity
community baseline, used as-is (no custom modifications), sourced from:
https://github.com/SwiftOnSecurity/sysmon-config

Chosen over Sysmon's defaults because default logging is extremely
noisy with a low signal-to-noise ratio. This is a widely-trusted,
community-vetted baseline rather than a custom-written config, which
also demonstrates familiarity with how the security community shares
and builds on shared detection tooling.

Installed with:
```
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
