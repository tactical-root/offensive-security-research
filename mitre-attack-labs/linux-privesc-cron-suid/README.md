# Linux Privilege Escalation & Persistence via SUID and Cron
**MITRE ATT&CK Mapping:** `T1548.001` (Abuse Elevation Control Mechanism: Setuid and Setgid) | `T1053.003` (Scheduled Task/Job: Cron)  
**Author:** Ryan Vansluytman

---

## Brief Description
This procedure outlines the incident response and detection workflow for identifying, analyzing, and mitigating attacks leveraging Unix Set User ID (SUID) misconfigurations (`T1548.001`) for local privilege escalation, followed by unauthorized scheduled task manipulation via `cron` (`T1053.003`) to maintain persistent root-level access. All procedures and simulations described herein are scoped for isolated virtual machine test environments or authorized target systems.

---

## Incident Trigger
An alert is triggered by an Endpoint Detection and Response (EDR) agent on an Ubuntu server (`srv-prod-db01`), flagging an abnormal execution sequence:
* **Trigger Event:** An unprivileged service account executed a root-owned binary (`/usr/bin/find` or `/bin/cp`) with an effective UID of `0` (`root`), immediately followed by the creation of an unexpected file inside `/etc/cron.d/`
* **Behavioral Anomaly:** Outbound network telemetry concurrently detected a periodic TCP connection attempt to an external, unclassified IP address on port `4444` occurring every 10 minutes.

---

## Initial Triage
Incident responders must classify the alert as abnormal, normal, or a false positive:

* **Abnormal (True Positive):**
  * The binary executed with SUID permissions is non-standard (e.g., matching known GTFOBins abuse primitives such as `find`, `vim`, or custom compiled binaries).
  * The cron configuration file points to an obfuscated script, a payload in `/tmp` or `/dev/shm`, or executes an interactive reverse shell (e.g., `nc`, `bash -i`).
* **Normal:**
  * Legitimate system administrative tasks involving standard utilities (such as `/usr/bin/passwd` or `/usr/bin/sudo`) executed during documented maintenance windows.
* **False Positive:**
  * Legitimate deployment pipelines (e.g., Ansible, CI/CD runners) dynamically configuring crontabs for routine database backups, log rotations, or internal compliance scans.

---

## Detection Criteria
* **Impacted Systems:** Linux distributions (RHEL, Ubuntu, Debian, CentOS) utilizing standard Unix discretionary access controls, POSIX permissions, and cron daemon implementations (`cron`, `crond`, `anacron`).
* **SUID Abuse:** Non-standard binaries residing outside baseline permission manifests with octal permissions `4000` (SUID) or `2000` (SGID) set.
* **Cron Abuse:** Newly created, modified, or hidden jobs within system crontabs or user spool directories executing binaries/scripts directly from world-writable directories (`/tmp`, `/var/tmp`, `/dev/shm`).

---

## Forensic Evidence Locations
* **Filesystem & Permission Attributes:**
  * `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs/`
  * Inode metadata and file timestamps (`stat`) for binaries exhibiting SUID/SGID permissions
* **System & Audit Logs:**
  * `/var/log/syslog` or `/var/log/cron` — execution records of scheduled cron tasks
  * `/var/log/auth.log` or `/var/log/secure` — authentication events, user privilege changes, and `sudo` executions
  * `/var/log/audit/audit.log` — Linux Audit Daemon (`auditd`) logs capturing `execve` and `setuid` syscalls
* **Threat Intelligence & Reference Repositories:**
  * Threat intelligence feeds cross-referencing outbound C2 IP addresses
  * [GTFOBins](https://gtfobins.github.io) documenting Unix binary privilege escalation vectors

---

## Investigation & Triage Commands
Execute the following ordered sequence in a controlled shell:

1. **Identify active network connections and associated processes:**
   ```bash
   ss -tulpn
   ```
   *(Provides immediate socket visibility without generating substantial system overhead.)*

2. **Audit all SUID binaries across the local filesystem against known baselines:**
   ```bash
   find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
   ```
   *(Audits file modes natively without third-party dependencies.)*

3. **Inspect all system-wide and user crontabs for persistence entries:**
   ```bash
   crontab -l -u root
   ls -la /etc/cron.*
   cat /var/spool/cron/crontabs/* 2>/dev/null
   ```

4. **Examine audit and authentication logs for binary executions and privilege changes:**
   ```bash
   ausearch -m EXECVE -ts recent
   grep -Ei "cron|session opened" /var/log/auth.log | tail -n 50
   ```
   *(Extracts non-repudiable kernel-level execution traces via `auditd`.)*

5. **Inspect running processes under UID `0` originating from unprivileged parent processes:**
   ```bash
   ps -eo user,pid,ppid,args --sort=user | grep root
   ```

---

## Containment & Mitigation
* **Immediate Containment:**
  * Isolate the affected host at the network layer (disable switch port or apply host firewall rules dropping all ingress/egress except an authorized out-of-band management console).
  * Terminate rogue cron processes and reverse shell PIDs (`kill -9 <PID>`).
  * Strip unauthorized SUID permissions from compromised binaries (`chmod u-s /path/to/binary`).
  * Remove malicious cron entries from `/etc/cron.*` or user crontab spools.
* **Long-Term Prevention:**
  * Deploy File Integrity Monitoring (FIM) via **Wazuh**, **OSSEC**, or `auditd` to alert on permission changes to system binaries and modifications to cron directories.
  * Mount temporary and user-writable partitions (`/tmp`, `/var/tmp`, `/dev/shm`) with the `nosuid`, `noexec`, and `nodev` flags in `/etc/fstab`.

---

## Eradication & Hardening
* **Eradication:**
  * Verify system binary integrity against vendor package hashes (`dpkg -V` on Debian/Ubuntu or `rpm -Va` on RHEL/CentOS) to detect trojanized utilities.
  * Remove unauthorized user accounts, rogue SSH keys in `/root/.ssh/authorized_keys`, and persistent cron tasks.
  * If kernel-level tampering or rootkit installation is suspected, back up non-executable critical data and rebuild from a verified golden image.
* **Recurrence Prevention:**
  * Enforce the **Principle of Least Privilege (PoLP)**, restricting `sudo` access and stripping unnecessary SUID/SGID bits across enterprise baselines.
  * Restrict cron access via `/etc/cron.allow` and `/etc/cron.deny` so only authorized service accounts can schedule jobs.
  * Automate configuration compliance auditing with **Lynis** or **OpenSCAP**.

---

## References
1. GTFOBins Contributors, *GTFOBins*, 2026. https://gtfobins.github.io
2. MITRE ATT&CK, *Scheduled Task/Job: Cron (T1053.003)*, 2026. https://attack.mitre.org/techniques/T1053/003/
3. MITRE ATT&CK, *Abuse Elevation Control Mechanism: Setuid and Setgid (T1548.001)*, 2026. https://attack.mitre.org/techniques/T1548/001/
4. The DFIR Report, *HTML Smuggling Leads to Domain Wide Ransomware*, Aug. 28, 2023. https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/
5. Kroll Cyber Threat Intelligence, *Cactus Ransomware: Cyber Threat Intelligence*, 2023. https://www.kroll.com/en/publications/cyber/cactus-ransomware-prickly-new-variant-evades-detection
