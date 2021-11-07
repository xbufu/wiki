---
title: "Domain OUs"
description: "Enumerating domain OUs."
lead: "Enumerating information about domain OUs using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:09:27+01:00
lastmod: 2021-11-07T18:09:27+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 40
toc: true
---

## Get OUs in a Domain

```powershell
# AD Module
Get-ADOrganizationalUnit -Filter * -Properties *

# PowerView
Get-NetOU -FullData
```

## Get GPO applied on an OU (Read GPOName from gplink attribute from Get-NetOU)

```powershell
# AD Module
Get-GPO -GUID "AB306569-220D-43FF-B03B-83E8F4EF8081"

# PowerView
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"
```

## Find all Computers in a given OU

```powershell
Get-DomainComputer -SearchBase "ldap://OU=..."
```

## Get the logged on Users for all Machines in any *server* OU in a particular Domain

```powershell
Get-DomainOU -Identity *server* -Domain <domain> | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -ComputerName $_}}
```
