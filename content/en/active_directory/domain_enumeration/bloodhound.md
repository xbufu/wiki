---
title: "BloodHound"
description: "Enumeration methods using Bloodhound."
lead: "Setup and enumeration using Bloodhound"
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 50
toc: true
---

## Setup

```bash
# Install bloodhound
apt install bloodhound

# Start console
neo4j console

# Open web console and login with default credentials: neo4j:neo4j
firefox http://localhost:7474/browser/

# Start bloodhound and login with credentials
bloodhound
```

## Get Loot with SharpHound.ps1

```powershell
# Default
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip

# Try to avoid detection
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip -ExcludeDC
```
