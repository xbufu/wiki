---
title: "ActiveDirectory Module"
description: "Setting up the ActiveDirectory PowerShell module."
lead: "Setting up the ActiveDirectory PowerShell module."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 100
toc: true
---

## Setup

### With Internet Access

```powershell
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
```

### Without Internet Access

```powershell
# If computer has no internet access, download repository
Import-Module .\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
Import-Module .\ADModule\ActiveDirectory\ActiveDirectory.psd1
```

### Check if Module has been imported correctly

```powershell
Get-Command -Module ActiveDirectory
```
