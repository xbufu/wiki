---
title: "Installation"
description: "Installation instructions for Active Directory."
lead: "Setting up Active Directory, Domain Controllers, DNS, and more."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "general"
weight: 20
toc: true
---

## Setup DNS

```powershell
# Install normal DNS server
Install-WindowsFeature DNS

# Register DNS records
cmd /c ipconfig -registerdns
```

## Install AD DS on Server Core

```powershell
# Install AD DS and management tools
Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools

# Install new forest and domain
Install-ADDSForest -DomainName "lab.local"
```

## Add Domain Controller

```powershell
# Add domain controller and prompt for credentials
Install-ADDSDomainController -DomainName "lab.local" -Credential (Get-Credential Lab\Administrator)
```

### Create DC from IFM Media

```bat
" Create directory for image
mkdir C:\ifm

" Launch ntdsutil
ntdsutil
ntdsutil: activate instance ntds
ntdsutil: ifm
ifm: create sysvol full c:\ifm
```

Transfer folder to target computer then run

```powershell
Install-ADDSDomainController -DomainName "lab.local" -Credential (Get-Credential Lab\Administrator) -InstallationMediaPath "C:\ifm"
```

### Clone DC

```powershell
# Get list of applications that do not support cloning
Get-ADDCCloningExcludedApplicationList

# Create list of applications that do support cloning
Get-ADDCCloningExcludedApplicationList -GenerateXml

# Create config file
New-ADDCCloneConfigFile -Static -IPv4Address "192.168.47.13" -IPv4DNSResolver "192.168.47.10" -IPv4SubnetMask "255.255.255.0" -CloneComputerName "DC04" -IPv4DefaultGateway "192.168.47.2"

# Shutdown computer and clone VM
Stop-Computer
```

## Join Computer To Domain

```powershell
# Add computer to domain and restart
Add-Computer -DomainName "lab.local" -Restart

# Rename computer and add to domain
Add-Computer -DomainName "lab.local" -NewName "test" -Restart
```
