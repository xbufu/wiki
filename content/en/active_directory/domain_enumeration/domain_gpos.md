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

## Display RSoP Summary Data

```powershell
gpresult /R

# AD Module
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html
```

## Get List of GPOs in current Domain

```powershell
# AD Module
Get-GPO -All

# PowerView
Get-NetGPO
Get-NetGPO | Select displayname
Get-NetGPO -ComputerName ws01.lab.local
Get-DomainGPO -ComputerIdentity windows1.testlab.local
```

## Get GPO(s) which use Restricted Groups or groups.xml for interesting Users

```powershell
Get-NetGPOGroup
```

## Get Users which are in a local Group of a Machine using GPO

```powershell
Find-GPOComputerAdmin -ComputerName ws01.lab.local
```

## Get Machines where the given User is a Member of a specific Group

```powershell
Find-GPOLocation -UserName user -Verbose
```

## Enumerate what Machines that a particular User/Group Identity has local Admin Rights to

```powershell
# Get-DomainGPOUserLocalGroupMapping == old Find-GPOLocation
Get-DomainGPOUserLocalGroupMapping -Identity <User/Group>
```

## Enumerate what machines that a given User in the specified Domain has RDP Access Rights to

```powershell
Get-DomainGPOUserLocalGroupMapping -Identity <USER> -Domain <DOMAIN> -LocalGroup RDP
```

## Export a CSV of all GPO Mappings

```powershell
Get-DomainGPOUserLocalGroupMapping | %{$_.computers = $_.computers -join ", "; $_} | Export-CSV -NoTypeInformation gpo_map.csv
```
