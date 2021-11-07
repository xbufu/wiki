---
title: "Kerbrute"
description: "Enumeration methods using Kerbrute."
lead: "User enumeration using Kerbrute by bruteforcing."
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

## Overview

- Get precompiled binary for OS from https://github.com/ropnop/kerbrute/releases
- Does not trigger failed log on event
- Brute-force by sending only a single UDP frame to the KDC
- Enumerate users on the domain from a wordlist

## Exploitation

```bash
# Username enumeration
kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
```
