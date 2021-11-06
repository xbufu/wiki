---
title: "DNS"
description: "Information about DNS in Active Directory."
lead: "Information and setup instructions for DNS in Active Directory."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "general"
weight: 30
toc: true
---

## General

- Active Directory relies on DNS
- Locate machines and resources on the same domain

## Setup DNS

```powershell
# Install normal DNS server
Install-WindowsFeature DNS

# Register DNS records
cmd /c ipconfig -registerdns
```
