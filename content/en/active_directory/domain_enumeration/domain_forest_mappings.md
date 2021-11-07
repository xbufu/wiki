---
title: "Domain Forest Mappings"
description: "Enumerating domain forest mappings."
lead: "Enumerating information about domain forest mappings using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:10:03+01:00
lastmod: 2021-11-07T18:10:03+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 80
toc: true
---

## Get Details about the current Forest

```powershell
# AD Module
Get-ADForest
Get-ADForest -Identity lab.local

# PowerView
Get-NetForest
Get-NetForest -Forest lab.local
```

## Get all Domains in the current Forest

```powershell
# AD Module
(Get-ADForest).Domains

# PowerView
Get-NetForestDomain
Get-NetForestDomain -Forest lab.local
```

## Get all Global Catalogs for the current Forest

```powershell
# AD Module
Get-ADForest | Select -ExpandProperty GlobalCatalogs

# PowerView
Get-NetForestCatalog
Get-NetForestCatalog -Forest lab.local
```

## Map Trusts of a Forest

```powershell
# AD Module
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'

# PowerView
Get-NetForestTrust
Get-NetForestTrust -Forest lab.local
```

## Map all Trusts in current Forest

```powershell
# PowerView
Get-NetForestDomain |  Get-NetDomainTrust
```
