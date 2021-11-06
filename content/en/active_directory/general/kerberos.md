---
title: "Kerberos"
description: "Information about Kerberos."
lead: "Information Kerberos, such as important terminology and the authentication process."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "general"
weight: 40
toc: true
---

## Introduction

- Default authentication service for AD domains
- Uses 3rd party ticket autorization as well as stronger encryption than NTLM

---

## Authentication Process

1. Client encrypts a timestamp with his NTLM hash and sends it to the KDC (`AS-REQ`)
2. KDC encrypts TGT with user NTLM, signs it and sends it back to the user (`AS-REP`). Only `krbtgt` can open and read TGT data
3. Clients encrypts TGT with `krbtgt` NTLM hash when requesting a TGS ticket (`TGS-REQ`)
4. KDC encrypts TGS with target service's NTLM hash and sends it back to the client (`TGS-REP`)
5. User connects to the server hosting the service on the appropriate port & presents the TGS (`AP-REQ`)
6. Service validates the ticket and checks weather the user can access it or not

---

## Terminology

### Ticket Granting Ticket (TGT)

Authentication ticket used to request service tickets from the TGS for specific resources from the domain.

### Key Distribution Center (KDC)

A service issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.

### Authentication Service (AS)

Issues TGTs to be used by the TGS i nthe domain to request access to other machines and service tickets.

### Ticket Granting Service (TGS)

Takes the TGT and returns a ticket to a machine on the domain.

### Service Principal Name (SPN)

Identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.

### KDC Long Term Secret Key (KDC LT Key)

KDC key is based on the KRBTGT service account. Used to encrypt the TGT and sign the PAC.

### Client Long Term Secret Key (Client LT Key)

Client key is based on the computer or service account. It is used to check the encrypted timestampt and encrypt the session key.

### Service Long Term Secret Key (Service LT Key)

The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.

### Session Key

Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.

### Privilege Attribute Certificate (PAC)

The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

---

## AS-REQ with Pre-Authentication

- Starts when a user requests a TGT from the KDC
- To validate the user and create a TGT for him, KDC must follow certain steps
  - User encrypts a timestamp NT hash and send it to the AS
  - KDC attempts to decrypt the timestampt using the user's NT hash
  - If successful, KDC will issue TGT and session key for the user

### Ticket Granting Ticket Contents

- TGT is provided by the user to KDC
- KDC validates ticket and returns service ticket
- Content:
  - Start/end/validity time
  - Service name
  - Target name
  - Client name
  - Session key
  - PCA
  - Signed with
    - Service LT Key
    - KDC LT Key

### Service Ticket Contents

- Contains two portions: service-provided portion & user-provided portion
- Service portion
  - User details
  - Session key
  - Encrypts the ticket with service account NTLM hash
- User portion
  - Validity timestamp
  - Session key
  - Encrypts with the TGT session key

---

## Kerberos Tickets Overview

- TGT comes in various formats
  - .kirbi for Rubeus
  - .ccache for Impacket
- Ticket is base64 encoded
- Once user gives TGT to server, it then
  - gets user details & session key
  - encrypts ticket with service NTLM hash
- KDC will authenticate TGT and return service ticket
- Normal TGT will only work for the target service
- KRBTGT allows you to get any service ticket to gain access to anything in the domain

---

## Attack Privilege Requirements

| Attack |Requirements |
| --- | --- |
| Kerbrute Enumeration | No domain access required  |
| Pass the Ticket | Access as a user to the domain required |
| Kerberoasting | Access as any user required |
| AS-REP Roasting | Access as any user required |
| Golden Ticket | Full domain compromise (domain admin) required  |
| Silver Ticket | Service hash required  |
| Skeleton Key | Full domain compromise (domain admin) required |
