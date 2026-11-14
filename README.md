# Offensive Security Research & Penetration Testing Labs

Structured penetration testing reports, adversary emulation write-ups, and post-exploitation research mapped to the **MITRE ATT&CK** framework. Each lab documents the technical attack mechanism, exploitation workflow, telemetry indicators, and actionable defensive remediation.

## Repository Structure

| Directory | Focus Area | Key Techniques & Tools |
| :--- | :--- | :--- |
| [`/mitre-attack-labs/linux-privesc-cron-suid`](./mitre-attack-labs/linux-privesc-cron-suid) | Linux Privilege Escalation & Persistence | SUID/SGID Binary Abuse (`T1548.001`), Cron Job Exploitation (`T1053.003`) |
| [`/mitre-attack-labs/ad-attack-paths`](./mitre-attack-labs/ad-attack-paths) | Active Directory Exploitation & Hardening | Kerberoasting, NTLM Relaying, Credential Dumping, GPO/RBAC Remediation |
| [`/htb-cpts-writeups`](./htb-cpts-writeups) | Retired Hack The Box & CPTS Assessments | Full-scope enumeration, foothold, lateral movement, and reporting |

## Methodology & Standards
* **Engagement Format:** Reports follow standard penetration testing conventions—Executive Summary, Attack Narrative, Technical Proof-of-Concept, and Remediation Steps.
* **OPSEC & Sanitization:** All lab artifacts use isolated RFC 1918 subnets (`192.168.x.x` / `10.x.x.x`), and public platform walkthroughs are strictly restricted to retired machines.
