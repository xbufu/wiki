---
title: "Kerberos Delegation"
description: "Information about Kerberos Delegation."
lead: "Information about Kerberos delegation, such as the authentication process and the different types."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "general"
weight: 50
toc: true
---

## What is Kerberos Delegation?

- Allows to "reuse the end-user credentials to access resources hosted on a different server"
- E.g. user authenticates to webserver, then webserver impersonates user to authenticate to database server
- But: Service account for web server must be trusted for delegation to impersonate user

## Authentication Process

- User provides credentials to DC
- DC returns TGT
- User requests TGS for web service on Web Server
- Web server service account uses the user's TGT to request TGS for the database server from the DC
- Web server service account connects to the database server as the user

## Types of Kerberos Delegation

### Unconstrained

- General/basic delegation
- Allows service to access any server on any computer in the domain

### Constrained

- Allows service to request access only to specified computers/resources
- If user is not using Kerberos authentication to authenticate to web server, Windows offers Protocol Transition to transition the request to Kerberos
