---
title: "ActiveDirectory Module"
description: "Enumeration methods using the ActiveDirectory PowerShell module."
lead: "Enumeration of the domain, users, groups, and computers using the ActiveDirectory PowerShell module."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 20
toc: true
---

## Enumeration using Native Executables and .NET Classes

```powershell
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```

## ActiveDirectory Module Installation

- https://github.com/samratashok/ADModule
- Will likely not get picked up by AV
- Works in CLM

```powershell
# If computer has internet access
iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory

# If computer has no internet access, download repository
Import-Module .\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
Import-Module .\ADModule\ActiveDirectory\ActiveDirectory.psd1

# Check if module has been imported correctly
Get-Command -Module ActiveDirectory
```

## Domains

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

## Users

```powershell
# Get list of users in current domain
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
Get-ADUser -Filter * -Properties * | Select Name

# Get list of all properties for users in current domain
Get-ADUser -Filter * -Properties * | Select -First 1 | Get-Member -MemberType *Property | Select Name
Get-ADUser -Filter * -Properties * | Select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}

# Search for a particular string in a user's attributes
Get-ADUser -Filter 'Description -Like "*built*"' -Properties Description | Select name,Description
```

## Computers

```powershell
# Get list of computers in current domain
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | Select Name

# Information about operating systems
Get-ADComputer -Filter 'OperatingSystem -Like "*Server 2016"' -Properties OperatingSystem | Select Name,OperatingSystem

# Check for live hosts (depends on ICMP)
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```

## Groups

```powershell
# Get all groups in current domain
Get-ADGroup -Filter * | Select Name
Get-ADGroup -Filter * -Properties *

# Get all groups containing the word "admin" in group name
Get-ADGroup -Filter 'Name -Like "*admin*"' | Select Name

# Get all members of Domain Admins group
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Get group membership for a user
Get-ADPrincipalGroupMembership -Identity student1
```

## Group Policy

- Security settings
- Registry-based policy settings
- GPP like start/shutdown/log-on/logff script settings
- Software installation
- Abused for privesc, backdoors, persistence

// To Do: Add installation for GroupPolicy Powershell module from RSAT

```powershell
# Get list of GPO in current domain
Get-GPO -All

# Provides RSoP
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html
```

## Organizational Units

```powershell
# Get OUs in a domain
Get-ADOrganizationalUnit -Filter * -Properties *

# Get GPO applied on an OU. Read GPOName from gplink attribute from Get-NetOU
Get-GPO -GUID "AB306569-220D-43FF-B03B-83E8F4EF8081"
```

## Access Control Lists

- Access Control Entries (ACE) correspond to individual permission or audits access
- Who has permission and what can be done on an object?
- Two types:
  - DACL -> Defines the permissions trustees (a user or group) have on an object
  - SACL - Logs success and failure audit messages when an object is accessed

```powershell
# Enumerate ACLs without resolving GUIDs
(Get-ACL 'CN=Domain Admins,CN=Users,DC=dc01,DC=dc02,DC=local').Access
```

## Trusts

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

```powershell
# Get a list of all domain trusts for the current domain
Get-ADTrust
Get-ADTrust -Filter * | Select Source,Target,Direction
Get-ADTrust -Identity test.lab.local
```

## Forest Mapping

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
