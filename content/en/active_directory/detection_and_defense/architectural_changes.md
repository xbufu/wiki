---
title: "Architectural Changes"
description: "Architectural changes for defense."
lead: "Architectural changes a user can make to the environment for defense."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "detection_and_defense"
weight: 999
toc: true
---

## LAPS - Local Administrator Password Solution

- Centralized storage of passwords in AD with periodic randomizing where read permissions are access controlled
- Computer objects have two new attributes ms mcs AdmPwd attribute stores the clear text password and ms mcs AdmPwdExpirationTime controls the password change
- Storage in clear text, transmission is encrypted
- With careful enumeration, it is possible to retrieve which users can access the clear text password providing a list of attractive targets!

## Credential Guard

- Now called, Windows Defender Credential Guard, it "uses virtualization based security to isolate secrets so that only privileges system software can access them"
- Effective in stopping PTH and Over PTH attacks by restricting access to NTLM hashes and TGTs
- As of Windows 10 1709, it is not possible to write Kerberos tickets to memory even if we have credentials.
- https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard
- Credentials for local accounts in SAM and Service account credentials from LSA secrets are NOT protected
- Credential Guard cannot be enabled on a domain contorller as it breaks authentication there
- Only available on the Windows 10 Enterprise edition and Server 2016
- Possible to replay service account credenttials for lateral movement even if credential guard is enabled

## Device Guard

- Now called, Windows Defender Device Guard, it is a group of features "designed to harden a system against malware attacks. Its focus is preventing malicious code from running by ensuring only known good code can run."
- Three primary components:
  - Configurable Code Integrity (CCI) Configure only trusted code to run
  - Virtual Secure Mode Protected Code Integirty Enforces CCI with Kernerl Mode (KMCI) and User Mode (UMCI)
  - Platform and UEFI Secure Boot Ensures boot binaries and firmware integrity
- https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control
- UMCI is something which interferes with most of the lateral movement attacks we have seen
- While it depends on the deployment (discussing which will be too lengthy), many well known application whitelisting bypasses signed binaries like csc.exe, MSBuild.exe etc. are useful for bypassing UMCI as well

## Protected Users Group

- Introduced in Server 2012 R2 for "better protection against credential theft" by not caching credentials in insecure ways
- A user added to this group:
  - Cannot use CredSSP and WDigest No more cleartext credentials caching
  - NTLM hash is not cached
  - Kerberos does not use DES or RC4 keys. No caching of clear text cred or long term keys.
- If the domain functional level is Server 2012 R2:
  - No NTLM authentication
    No DES or RC4 keys in Kerberos pre auth
  - No delegation (constrained or unconstrained)
  - No renewal of TGT beyond initial for hour lifetime Hardcoded, unconfigurable "Maximum lifetime for user ticket" and "Maximum lifetime for user ticket
- Needs all domain control to be at least Server 2008 or later (because AES keys)
- Not recommended by MS to add DAs and EAs to this group without testing "the potential impact" of lock out
- No cached logon ie.e no offline sign on
- Having computer and service accounts in this group is useless as their credentials will always be present on the host machine

## Privileged Administrative Workstations (PAWs)

- A hardened workstation for performing sensitive tasks like
  - administration of domain controllers
  - cloud infrastructure
  - sensitive business functions etc.
- Can provide protection from
  - phishing attacks
  - OS vulnerabilities
  - credential replay attacks
- Admin Jump servers to be accessed only from a PAW, multiple strategies
  - Separate privilege and hardware for administrative and normal tasks
  - Having a VM on a PAW for user tasks

## Active Directory Administrative Tier Model

- Composed of three levels only for administrative accounts
- Control restrictions: what admins control
- Logon restrictions: where admins can log-on to

### Tier 0

Accounts, Groups and computers which have privileges across the enterprise like domain controllers, domain admins, enterprise admins

### Tier 1

- Accounts, Groups and computers which have access to resources having significant amount of business value
- A common example role is server administrators who maintain these operating systems with the ability to impact all enterprise services

### Tier 2

- Administrator accounts which have administrative control of a significant amount of business value that is hosted on user workstations and devices
- Examples include Help Desk and computer support administrators because they can impact the integrity of almost any user data

## ESAE (Enhanced Security Admin Environment)

- Dedicated administrative forest for managing critical assets like
  - administrative users
  - groups
  - computers
- Since a forest is considered a security boundary rather than a domain, this model provides enhanced security controls
- The administrative forest is also called the Red Forest
- Administrative users in a production forest are used as standard non privileged users in the administrative forest
- Selective Authentication to the Red Forest enables stricter security controls on logon of users from non-administrative forests

## Further Reading

- [Securing Privileged Access](https://docs.microsoft.com/en-us/security/compass/overview)
- [Best Practices for Securing Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
