---
title: "Files and Shares"
description: "Enumerating files & Shares with PowerView."
lead: "Enumerating files & Shares using PowerView."
date: 2021-11-07T18:20:24+01:00
lastmod: 2021-11-07T18:20:24+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 90
toc: true
---

## Find Shares on hosts in current Domain

```powershell
Invoke-ShareFinder -Verbose
```

## Find Shares from other Domain

```powershell
Invoke-ShareFinder -Domain lab.local
```

## Exclude default Shares

```powershell
Invoke-ShareFinder -ExcludeStandard
```

## Show only Shares the current User has Access to

```powershell
Invoke-ShareFinder -CheckShareAccess
```

## Find sensitive Files on Computers

```powershell
Invoke-FileFinder -Verbose
```

## Get all Fileservers

```powershell
Get-NetFileServer
```

## Use alternate Credentials when searching for Files

```powershell
# Find-InterestingDomainShareFile == old Invoke-FileFinder
$Password = "PASSWORD" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("DOMAIN\user",$Password)
Find-InterestingDomainShareFile -Domain Domain -Credential $Credential
```
