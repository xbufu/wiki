---
title: "Domain Trusts"
description: "Enumerating domain trusts."
lead: "Enumerating information about domain trusts using the ActiveDirectory PowerShell module and PowerView."
date: 2021-11-07T18:09:42+01:00
lastmod: 2021-11-07T18:09:42+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "domain_enumeration"
weight: 70
toc: true
---

## General

- Relationship between two domains or forest
- Trusted Domain Objects (TDOs) represent trust relationship in a domain
- Types of trusts
  - One-way: users in trusted domain can access resources in the trusting domain
  - Two-way trust: users of both domains can access resources in the other domain
  - Transitive: If A and B trust each other and B and C trust each other, A and C also trust each other (default between domains in same forest)
  - Non-transitive: cannot be extended to other domains in the forest (default between two domains in different forests)
  - Automatic trust: created automatically when creating new subdomain (parent-child, tree-root)
  - Shortcut trusts: used to reduce access time in complex trust scenarios
  - External trusts: between two domains in different forests when forests do not have a turst relationships
  - Forest trusts: between forest root domains

## Get all Trusts for the current Domain

```powershell
# AD Module
Get-ADTrust
Get-ADTrust -Filter * | Select Source,Target,Direction

# PowerView
Get-NetDomainTrust
```

## Get Trusts for specific Domain

```powershell
# AD Module
Get-ADTrust -Identity test.lab.local

# PowerView
Get-NetDomainTrust -Domain test.lab.local
```
