---
title: "Domain Groups"
description: "Enumerating domain groups."
lead: "Enumerating information about domain groups using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T17:58:37+01:00
lastmod: 2021-11-07T17:58:37+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 30
toc: true
---

## Get all Groups in current Domain

```powershell
# AD Module
Get-ADGroup -Filter * | Select Name
Get-ADGroup -Filter * -Properties *

# PowerView
Get-NetGroup
Get-NetGroup -FullData
```

## Get Information about Groups in other Domain

```powershell
Get-NetGroup -Domain lab.local
```

## Get all Groups containing the Word "admin" in Group Name

```powershell
# AD Module
Get-ADGroup -Filter 'Name -Like "*admin*"' | Select Name

# PowerView
Get-NetGroup "*admin*"
```

## Get Information about specific Group

```powershell
Get-NetGroup -FullData "Domain Admins"
```

## Get all Members of Domain Admins Group

```powershell
# AD Module
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# PowerView
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
```

## Get List of Enterprise Admins, only available from Forest Root

```powershell
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain lab.local
```

## Get Group Membership for a User

```powershell
# AD Module
Get-ADPrincipalGroupMembership -Identity student1

# PowerView
Get-NetGroup -UserName "student1"
```

## List all local Groups on a Machine (needs Administrator Privileges on non-dc Machines)

```powershell
Get-NetLocalGroup -ComputerName dc.lab.local -ListGroups
```

## Get Members of all local Groups on a Machine (needs Administrator Privileges on non-dc Machines)

```powershell
Get-NetLocalGroup -ComputerName dc.lab.local -Recurse
```

## Find linked DA Accounts using Name Correlation

```powershell
Get-DomainGroupMember 'Domain Admins' | %{Get-DomainUser $_.membername -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname}
```

## Find any Machine Accounts in Privileged Groups

```powershell
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'}
```

## Enumerate all Groups that don't have a global Scope, returning just Group Names

```powershell
Get-DomainGroup -GroupScope NotGlobal -Properties name
```
