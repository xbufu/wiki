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

## Get List of Computers in current Domain

```powershell
# AD Module
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | Select Name

# PowerView
Get-NetComputer
Get-NetComputer -FullData
```

## Check for live Hosts (depends on ICMP)

```powershell
# AD Module
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}

# PowerView
Get-NetComputer -Ping
```

## Information about Operating Systems

```powershell
# AD Module
Get-ADComputer -Filter 'OperatingSystem -Like "*Server 2016"' -Properties OperatingSystem | Select Name,OperatingSystem

# PowerView
Get-NetComputer -OperatingSystem "*Server 2016"
Get-NetComputer -FullData | select dnshostname,operatingsystem
```

## Get list of sessions on Computer

```powershell
# PowerView
Get-NetSession -ComputerName "dc01.lab.local"
```

## Find any Computers with Constrained Delegation set

```powershell
# PowerView
Get-DomainComputer -TrustedToAuth
```

## Find all Servers that allow Unconstrained Delegation

```powershell
# PowerView
Get-DomainComputer -Unconstrained
```

## Return the local Groups of a remote Server

```powershell
# PowerView
Get-NetLocalGroup SERVER.domain.local
```

## Return the local Group Members of a remote Server using Win32 API Methods (faster but less info)

```powershell
# PowerView
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local
```

## Enumerates Computers in the current Domain with 'outlier' Properties

```powershell
# PowerView
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```
