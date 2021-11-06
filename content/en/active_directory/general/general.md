---
title: "General Information"
description: "General information about Active Directory."
lead: "Introduction to Active Directory components, objects, and roles."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "general"
weight: 10
toc: true
---

## Introduction

- Used to manage Windows domain networks
- "Phone book" for Windows -> stores information about computers, users, etc.
- Authentication uses Kerberos tickets
- Can be exploited using intended functionality

## Physical AD Components

- Domain controller server -> AD DS server role installed
- Domain controllers
  - Host copy of AD DS directory store
  - Provides authentication & authorization
  - Replicate updates to other DCs in the domain and forest
  - Administrative access to manage user accounts and network resources
- AD DS data store
  - Contains db files and processes that store and manage directory information for users, services, and applications
  - Consists of the `Ntds.dit` file
  - Is stored by default in the `%SystemRoot%\NTDS` folder on all DCs
  - Accessible only through the DC processes and protocols

## Logical AD Components

- AD DS schema
- Every type of object that can be stored
- Enforces rules for object creation & configuration

| Object Types | Function | Examples |
| --- | --- | --- |
| Class Object | What objects can be created in the directory | User, Computer |
| Attribute Object | Information that can be attached to an object | Display name |

### Domains

- Used to group and manage objects in an organization
- Administartive boundary for applying policies to groups and objects
- Replication boundary for replicating data between domain controllers
- Authentication & authorization boundary that provides a way to limit the scope of access to resources
  
### Trees

- Hierarchy of domains in AD DS
- All domains in the tree
  - Share contiguous namepsace with parent domain
  - Can have additional child domains
  - By default create a two-way transitive trust with other domains

### Forest

- Collection of one or more domain trees
- Share a common
  - schema
  - configuration partition
  - global catalog to enable searching
- Enable trusts between all domains in the forest
- Share the Enterprise Admins and Schema Admins groups

### Organization Units (OUs)

- AD containers that can contain users, groups, computer and other OUs
- Used to
  - Represent organization hierarchically and logically
  - Manage a collection of objects in a consistent way
  - Delegate permissions to administer groups of objects
  - Apply policies
- Separate components only for applying GP
- Don't mix users and computers

### Trusts

- Provide mecahnism for users to gain access to resources in antoher domain
- All domains in a forest trust all other domains in the forest
- Can extend outside the forest
- Types of trusts
  - Directional
  - Transitive
  
### Objects

- User
- InetOrgPerson
- Contacts
- Groups
- Computers
- Printers
- Shared folders

### Flexible Single Master Operations (FSMO) Roles

#### Schema Master

- Performs updates to the AD schema such as ADPREP/FORESTPREP, MS Exchange
- Must be online during schema updates
- Generally placed on the forest root PDC

#### Domain Naming Master

- Adds and removes domains and application partitions to and from the AD forest
- Must be online when domains and application partitions in a forest are added or removed
- Generally placed on the forest root PDC

#### PDC Emulator

- Manages password changes for computer and user accounts on replica domain controllers
- Consulted by replica domain controllers where service authentication requests have mismatched passwords
- Target DC for Group Policy updates
- Usually also the single authorative time server
- Target DC for legacy applications that perform writable operations and for some admin tools
- Must be online and accessible at all times
- Generally placed on higher-performance hardware in a reliable hub site alongside other DCs

#### RID Master

Allocates active and standby RID pools to replica DCs in the same domain
Must be online for newly-promoted DCs to obtain a local RID pool or when existing DCs must update their current or standby RID pool allocation
Generally placed on the forest root PDC

#### Infrastructure Master

- Updates cross-domain references and phantoms/tombstones from the Global Catalog
- A Separate infrastructure master is created for each application partition including the default forest-wide and domain-wide application partitions
- Can be placed on any DC in single-domain forest
- Generally placed on a DC that is not a Global Catalog in a multi-domain forest except when all DCs in the forest are Global Catalog then it can be placed on any DC
