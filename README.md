# Home Lab SOC Project

A cybersecurity home lab simulating real-world attacks and
automated detection using industry-standard security tools.
Built to demonstrate SOC analyst skills including
reconnaissance, exploitation, log analysis, and SIEM
detection rule development.

---

## Project Overview

This project covers the complete attack and defense lifecycle:

- Network reconnaissance against a vulnerable target
- Three distinct exploitation techniques achieving root access
- SIEM deployment with log ingestion from the target machine
- Four automated detection rules mapped to MITRE ATT&CK

---

## Lab Environment

| Component | Technology               | IP              |
| --------- | ------------------------ | --------------- |
| Attacker  | Kali Linux 2024.3        | 192.168.56.107  |
| Target    | Metasploitable 2         | 192.168.56.106  |
| SIEM      | Splunk Enterprise 10.4.1 | 192.168.56.1    |
| Network   | VirtualBox Host-Only     | 192.168.56.0/24 |

---

## Attacks Executed

| Attack                | CVE/CWE       | Service  | Result            |
| --------------------- | ------------- | -------- | ----------------- |
| vsftpd 2.3.4 Backdoor | CVE-2011-2523 | FTP:21   | Root shell        |
| UnrealIRCd Backdoor   | CVE-2010-2075 | IRC:6667 | Root shell        |
| SSH Brute Force       | CWE-307       | SSH:22   | Valid credentials |

---

## Detection Rules (Splunk)

| Rule                               | Trigger                 | MITRE Technique |
| ---------------------------------- | ----------------------- | --------------- |
| SSH Brute Force Detected           | >5 failed logins        | T1110.001       |
| Successful Login After Brute Force | Accepted password event | T1078           |
| FTP Backdoor Activity Detected     | vsftpd activity         | T1190           |
| High Volume Failed Logins          | >10 failures per minute | T1110           |

---

## Repository Structure

home-lab-project/
├── README.md
├── phase1-setup/
│ └── network-setup.md
├── phase2-reconnaissance/
│ ├── nmap-scan.md
│ └── nmap-results.png
├── phase3-exploitation/
│ ├── attacks.md
│ ├── vsftpd-exploit.png
│ ├── unreal-ircd-exploit.png
│ └── hydra-ssh-brute.png
├── phase4-splunk/
│ ├── detection-rules.md
│ ├── splunk-failed-password.png
│ ├── splunk-passed-password.png
│ ├── splunk-vsftpd.png
│ ├── splunk-stats-by-host.png
│ └── splunk-alerts-list.png
└── reports/
└── final-report.md

---

## Tools Used

- Nmap 7.99 — Network reconnaissance
- Metasploit Framework 6.4.135 — Exploitation
- Hydra 9.7 — Brute force credential attack
- Splunk Enterprise 10.4.1 — SIEM and detection
- Kali Linux 2024.3 — Attack platform
- VirtualBox — Lab virtualization

---

## Skills Demonstrated

- Network scanning and enumeration
- CVE-based exploitation using Metasploit
- Brute force attack execution and analysis
- SIEM deployment and configuration
- Log ingestion via UDP syslog
- SPL (Splunk Processing Language) query writing
- Detection rule development mapped to MITRE ATT&CK
- Security assessment report writing
