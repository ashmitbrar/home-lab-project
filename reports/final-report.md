# Security Assessment Report

## Home Lab: Attack Detection & SIEM Implementation

**Analyst:** Ashmit Brar  
**Lab Environment:** VirtualBox Isolated Network

---

## Executive Summary

This report documents a complete offensive and defensive
security assessment conducted in an isolated home lab
environment. Three attacks were executed against a
deliberately vulnerable target machine using industry-standard
penetration testing tools. All attacks were successfully
detected using a Splunk SIEM deployment with four custom
detection rules.

The assessment demonstrates a full SOC analyst workflow:
reconnaissance, exploitation, log analysis, and automated
detection — covering the complete attack lifecycle from
initial access to defender response.

**Key Findings:**

- 3 critical vulnerabilities successfully exploited
- 2 supply chain backdoors providing instant root access
- 1 successful brute force attack via default credentials
- 3,266 attack events captured and analyzed in Splunk
- 4 automated detection rules deployed and validated

---

## Lab Environment

| Component        | Details                               |
| ---------------- | ------------------------------------- |
| Attacker Machine | Kali Linux 2024.3 — 192.168.56.107    |
| Target Machine   | Metasploitable 2 — 192.168.56.106     |
| SIEM Platform    | Splunk Enterprise 10.4.1              |
| Network Type     | VirtualBox Host-Only (fully isolated) |
| Host Machine     | Windows 11 — 192.168.56.1             |

### Network Diagram

┌─────────────────────────────────────────────┐
│ VirtualBox Host-Only Network │
│ 192.168.56.0/24 │
│ │
│ ┌──────────────┐ ┌──────────────────┐ │
│ │ Kali Linux │─────▶│ Metasploitable │ │
│ │192.168.56.107│ │ 192.168.56.106 │ │
│ └──────────────┘ └────────┬─────────┘ │
│ │ syslog │
│ ┌────────▼─────────┐ │
│ │ Windows Host │ │
│ │ Splunk SIEM │ │
│ │ 192.168.56.1 │ │
│ └──────────────────┘ │
└─────────────────────────────────────────────┘

---

## Phase 1: Reconnaissance

### Tool: Nmap 7.99

### Command:

nmap -sS -sV -O -p- 192.168.56.106

### Key Findings

| Port | Service   | Version            | Risk Level |
| ---- | --------- | ------------------ | ---------- |
| 21   | FTP       | vsftpd 2.3.4       | Critical   |
| 22   | SSH       | OpenSSH 4.7p1      | High       |
| 23   | Telnet    | Linux telnetd      | High       |
| 80   | HTTP      | Apache 2.2.8       | High       |
| 1524 | Bindshell | Root shell         | Critical   |
| 3306 | MySQL     | 5.0.51a            | High       |
| 6667 | IRC       | UnrealIRCd 3.2.8.1 | Critical   |
| 5900 | VNC       | Protocol 3.3       | High       |

**Total open ports: 30**  
**Operating System: Linux 2.6.9 - 2.6.33 (Ubuntu 8.04)**

### Notes

The target exposed 30 open ports running severely outdated
software across all services. Multiple services had known
public exploits available. The attack surface was extremely
large a properly hardened system would expose only the
minimum required ports and run only actively maintained
software versions.

---

## Phase 2: Exploitation

### Attack 1: vsftpd 2.3.4 Backdoor (CVE-2011-2523)

**Target:** 192.168.56.106:21 (FTP)  
**Tool:** Metasploit Framework 6.4.135  
**CVSS Score:** 10.0 Critical

**Description:**  
CVE-2011-2523 is a supply chain attack where malicious code
was inserted into the vsftpd 2.3.4 source code before public
distribution. Sending a username containing ":)" triggers a
root shell on port 6200. No authentication required.

**Result:** Root shell obtained  
**Evidence:** uid=0(root) gid=0(root) confirmed

**MITRE ATT&CK:**

- T1190 — Exploit Public-Facing Application
- T1078.003 — Valid Accounts: Local Accounts

---

### Attack 2: UnrealIRCd 3.2.8.1 Backdoor (CVE-2010-2075)

**Target:** 192.168.56.106:6667 (IRC)  
**Tool:** Metasploit Framework 6.4.135  
**CVSS Score:** 10.0 Critical

**Description:**  
CVE-2010-2075 is another supply chain backdoor inserted into
UnrealIRCd before distribution. Sending "AB;" to the IRC
service executes arbitrary commands as root. No authentication
required.

**Result:** Root shell obtained  
**Evidence:** uid=0(root) gid=0(root) confirmed

**MITRE ATT&CK:**

- T1190 — Exploit Public-Facing Application
- T1059 — Command and Scripting Interpreter

---

### Attack 3: SSH Brute Force (CWE-307)

**Target:** 192.168.56.106:22 (SSH)  
**Tool:** Hydra v9.7  
**Severity:** High

**Description:**  
The SSH service had no account lockout policy, no rate
limiting, and was configured with default credentials.
Hydra automated repeated login attempts until valid
credentials were found.

**Result:** Valid credentials found — msfadmin:msfadmin  
**Time to compromise:** 13 seconds  
**Attempts made:** 5 (with targeted wordlist)

**MITRE ATT&CK:**

- T1110.001 — Brute Force: Password Guessing
- T1078 — Valid Accounts

---

### Exploitation Summary

| Attack              | CVE/CWE       | Port | Result            | Time    |
| ------------------- | ------------- | ---- | ----------------- | ------- |
| vsftpd Backdoor     | CVE-2011-2523 | 21   | Root shell        | <30 sec |
| UnrealIRCd Backdoor | CVE-2010-2075 | 6667 | Root shell        | <30 sec |
| SSH Brute Force     | CWE-307       | 22   | Valid credentials | 13 sec  |

All three attacks achieved full unauthorized access in under
30 seconds each. Zero privilege escalation was required on
any attack — all resulted in immediate root level access.

---

## Phase 3: SIEM Detection

### Platform: Splunk Enterprise 10.4.1

### Log Ingestion

Metasploitable system and authentication logs were forwarded
to Splunk via UDP syslog on port 514. Over 1,000 log events
were ingested and indexed for analysis.

### Attack Evidence in Splunk

**SSH Brute Force:**

- 3,266 "Failed password" events captured
- 3,253 attributed to host metasploitable
- Attack timeline clearly visible in event timestamps
- Source IP 192.168.56.107 identified across all events

**Successful Compromise:**

- "Accepted password" event captured following brute force
- Complete kill chain documented in SIEM logs
- Timeline shows failed attempts immediately preceding success

**FTP Backdoor:**

- vsftpd service activity logged
- Service presence on target confirmed in SIEM

---

## Detection Rules

### Rule 1: SSH Brute Force Detected

index=main "Failed password" | stats count by host
| where count > 5
Detects any host generating more than 5 failed SSH attempts.  
**MITRE:** T1110.001 | **Severity:** High

---

### Rule 2: Successful Login After Brute Force

index=main "Accepted password for msfadmin"
| stats count by host
Detects successful authentication following brute force pattern.  
**MITRE:** T1078 | **Severity:** Critical

---

### Rule 3: FTP Backdoor Activity Detected

index=main "vsftpd" | stats count by host
Detects any vsftpd service activity — FTP should not be
running in a hardened environment.  
**MITRE:** T1190 | **Severity:** Critical

---

### Rule 4: High Volume Failed Logins

index=main "Failed password" | bucket \_time span=1m
| stats count by \_time host | where count > 10
Detects more than 10 failed logins within any single
one-minute window — catches attack velocity rather than
just total count.  
**MITRE:** T1110 | **Severity:** High

---

### Critical Priority

**1. Patch all software immediately**  
vsftpd 2.3.4 and UnrealIRCd 3.2.8.1 contain known backdoors
from compromised supply chains. These services must be
updated or removed immediately. Running software from 2008
in any environment is indefensible.

**2. Remove unnecessary services**  
30 open ports is an enormous attack surface. Only expose
services that are actively required. Telnet, FTP, IRC,
rsh, rlogin, and rexec should all be disabled — none of
these have legitimate use in a modern environment.

**3. Eliminate default credentials**  
msfadmin:msfadmin was cracked in 13 seconds. All default
credentials must be changed before deployment. Implement
a credential management policy requiring strong unique
passwords or certificate-based authentication.

### High Priority

**4. Implement account lockout**  
SSH had no lockout policy allowing unlimited login attempts.
Deploy fail2ban or equivalent to block source IPs after
3-5 failed attempts within 60 seconds.

**5. Enforce SSH key-based authentication**  
Disable password-based SSH authentication entirely.
Certificate-based authentication eliminates brute force
as an attack vector.

**6. Implement network segmentation**  
No service should be directly reachable from an attacker
machine without passing through a firewall. Deploy network
ACLs to restrict access to only required ports from
authorized source IPs.

### Ongoing

**7. Deploy SIEM with tuned detection rules**  
The four detection rules implemented in this assessment
provide baseline coverage. In production, tune thresholds
based on observed baseline behavior and integrate with a
ticketing system for automated incident creation.

**8. Run regular vulnerability scans**  
An Nmap scan revealed the entire attack surface in under
3 minutes. Regular internal vulnerability scanning would
identify these issues before an attacker does.

---

## Conclusion

This assessment demonstrated that three critical vulnerabilities
on a single target machine could be exploited to achieve full
root access in under 30 seconds per attack with no specialized
skills required beyond running Metasploit modules. All attacks
were successfully detected through Splunk SIEM log analysis.

The most significant finding is not any individual vulnerability
but the overall security posture, outdated software, default
credentials, excessive exposed services, and no detective
controls represent systemic failures across people, process,
and technology. The SIEM deployment demonstrates that with
proper log collection and detection rules, these attacks are
entirely visible and alertable.

A SOC analyst monitoring this environment with the four
detection rules deployed would have received alerts within
60 seconds of each attack beginning, enabling rapid
containment before significant damage occurred.

---

## Tools Used

| Tool                 | Version | Purpose                |
| -------------------- | ------- | ---------------------- |
| Nmap                 | 7.99    | Network reconnaissance |
| Metasploit Framework | 6.4.135 | Exploitation           |
| Hydra                | 9.7     | Brute force            |
| Splunk Enterprise    | 10.4.1  | SIEM and detection     |
| VirtualBox           | Latest  | Lab virtualization     |
| Kali Linux           | 2024.3  | Attack platform        |

---

## References

- CVE-2011-2523: https://nvd.nist.gov/vuln/detail/CVE-2011-2523
- CVE-2010-2075: https://nvd.nist.gov/vuln/detail/CVE-2010-2075
- CWE-307: https://cwe.mitre.org/data/definitions/307.html
- MITRE ATT&CK: https://attack.mitre.org
- Metasploit Framework: https://www.metasploit.com
- Splunk Documentation: https://docs.splunk.com
