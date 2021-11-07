---
title: "Domains"
description: "Enumerating domains."
lead: "Enumerating information about domains using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T17:46:09+01:00
lastmod: 2021-11-07T17:46:09+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 5
toc: true
---

## Get current Domain

```powershell
# AD Module
Get-ADDomain

# PowerView
Get-NetDomain
```

## Get Object of another Domain

```powershell
# AD Module
Get-ADDomain -Identity lab.local

# PowerView
Get-NetDomain -Domain lab.local
```

## Get Domain SID for current Domain

```powershell
# AD Module
(Get-ADDomain).DomainSID

# PowerView
Get-DomainSID
```

## Get Domain Policy for current Domain

```powershell
# PowerView
Get-DomainPolicy
(Get-DomainPolicy)."System Access"
```

## Get Password Policy for another Domain

```powershell
# PowerView
(Get-DomainPolicy -Domain lab.local)."System Access"
```

## Get Kerberos Policy for e.g. Mimikatz Golden Tickets

```powershell
# PowerView
(Get-DomainPolicy -Domain lab.local)."Kerberos Policy"
```

## Get Domain Controllers for current Domain

```powershell
# AD Module
Get-ADDomainController

# PowerView
Get-NetDomainController
```

## Get Domain Controllers for another Domain

```powershell
# AD Module
Get-ADDomainController -DomainName lab.local -Discover

# PowerView
Get-NetDomainController -Domain lab.local
```

## Enumerate all Gobal Catalogs in the Forest

```powershell
# PowerView
Get-ForestGlobalCatalog
```

## Turn a List of Computer Short Names to FQDNs, using a Global Catalog

```powershell
# PowerView
gc computers.txt | % {Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_)" -Properties dnshostname}
```

## Enumerate the current Domain Controller Policy

```powershell
# PowerView
$DCPolicy = Get-DomainPolicy -Policy DC
$DCPolicy.PrivilegeRights # user privilege rights on the dc...
```

## Enumerate the current Domain Policy

```powershell
# PowerView
$DomainPolicy = Get-DomainPolicy -Domain bufu-sec.local
$DomainPolicy.KerberosPolicy # useful for golden tickets ;)
$DomainPolicy.SystemAccess # password age/etc.
```
