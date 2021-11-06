---
title: "Microsoft Advanced Threat Analytics (ATA)"
description: "Information about Microsoft ATA."
lead: "General information and bypass methods for Microsoft ATA."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "detection_and_defense"
weight: 999
toc: true
---

## General

- Traffic destined for Domain Controllers is mirrored to ATA sensors
- Use activity profile is build over time, i.e.
  - use of computers
  - credentials
  - log on machines
- Collects Event 4776 (The DC attempted to validate the credentials for an account) to detect credential replay attacks
- Can detect behavioral anomalies
- Useful for detecting:
  - Recon: account enum, netsession enum
  - Compromised Credentials Attacks: bruteforce, high privilege account/service account exposed in clear text, honey token, unusual protocol (NTLM and Kerberos)
  - Credential/Hash/Ticket Replay attacks

## Bypassing ATA

- Avoid talking to the DC as long as possible
- Try to blend in with normal traffic
