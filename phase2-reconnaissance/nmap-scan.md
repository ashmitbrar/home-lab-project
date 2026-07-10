# Phase 2: Reconnaissance

## Tool Used

Nmap 7.99

## Command

nmap -sS -sV -O -p- 192.168.56.106

## Objective

Perform a full port scan against the target to identify open ports,
running services, service versions, and operating system.

## Results Summary

- Total open ports: 30
- Operating System: Linux 2.6.9 - 2.6.33
- Target hostname: metasploitable.localdomain

## Key Findings

| Port    | Service          | Version                   | Risk                                    |
| ------- | ---------------- | ------------------------- | --------------------------------------- |
| 21      | FTP              | vsftpd 2.3.4              | CRITICAL — known backdoor vulnerability |
| 23      | Telnet           | Linux telnetd             | HIGH — cleartext credentials            |
| 80      | HTTP             | Apache 2.2.8              | HIGH — outdated, known CVEs             |
| 1524    | Bindshell        | Metasploitable root shell | CRITICAL — open root shell              |
| 3306    | MySQL            | 5.0.51a                   | HIGH — outdated database exposed        |
| 6667    | IRC              | UnrealIRCd                | CRITICAL — known backdoor vulnerability |
| 5900    | VNC              | protocol 3.3              | HIGH — remote desktop exposed           |
| 512-514 | rexec/rlogin/rsh | netkit                    | HIGH — legacy cleartext remote access   |

## Analyst Notes

Target is running severely outdated software across all services.
Multiple services have known public exploits available. The presence
of an open root shell on port 1524 indicates this machine is
intentionally configured as a vulnerable target for security testing.
