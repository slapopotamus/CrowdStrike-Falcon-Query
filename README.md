## 🎯 Overview

This repository serves as a centralized knowledge base for high-fidelity CrowdStrike Query Language (CQL) / LogScale queries. Each markdown file contains:
* **The Query:** Ready-to-copy LogScale syntax.
* **Context:** Detailed explanations of the tactics, techniques, and procedures (TTPs) being detected.
* **MITRE ATT&CK Mappings:** Relevant techniques mapped to the framework.
* **False Positives & Tuning:** Guidance on filtering out benign enterprise behavior to reduce alert fatigue.

---

## 📂 Query Categories

### 🛡️ Vulnerability & Exploit Detection
Detect active exploitation and systemic crashes associated with specific CVEs.
* `CVE-2026-20952`
* `CVE-2025-62221 - Windows Cloud Filter Driver Crash Detection`

### 🕵️ Incident Response & Lateral Movement
Track anomalous logons, unauthorized remote access, and network tunneling.
* `IR: Lateral Movement - RDP & Remote Admin Logon Tracking`
* `Interactive User Logon Tracking`
* `Privileged Local Logon Monitoring (Workstations)`
* `RDP Logon Activity Summary`
* `Remote Port Forwarding via Plink - Unauthorized RDP Tunneling Detection`
* `Remote Monitoring and Management (RMM) Tool Detection`

### 🥷 Defense Evasion & Obfuscation
Identify attempts to hide payloads, bypass defenses, or alter secure system states.
* `Certutil Remote Payload Download Detection`
* `Non-Browser Processes Using DNS-over-HTTPS`
* `Plaintext Password Handling - Process Command Line Discovery`
* `PowerShell Encoded Command Deobfuscation and Analysis`
* `PowerShell Steganography Detection (Tuoni C2 Framework)`
* `Pre-Ransomware Inhibiting System Recovery (Shadow Copy Deletion)`

### ☠️ APT & Threat Actor Campaigns
Specific indicators of compromise (IOCs) and behavioral detections for Advanced Persistent Threats.
* `Lotus Blossom - Chrysalis APT - Campaign Indicator Detection`
* `The Chrysalis Backdoor - Lotus Blossom (APT30) Hash Match`

### ☁️ Identity, Cloud & Network
Detect weak authentication protocols, unauthorized firewall drops, and Entra ID (Azure AD) token theft.
* `Entra ID / OAuth2 Authorization Code Interception Detection` *(Token Theft / AiTM)*
* `NTLM Weak Authentication and Key Length Detection`
* `Cisco FTD - Enhanced External Threat Analysis & Deny Reason Correlation`

---

## 🚀 Usage

1. **Navigate** to the specific `.md` file that matches your hunting objective.
2. **Review** the header comments in the file for context, prerequisites, and expected false positives.
3. **Copy** the query block.
4. **Paste** the query into your CrowdStrike Falcon **Investigate** or **LogScale** search bar.
5. **Tune** the query as needed for your specific environment (e.g., adding exclusions for known-good management IPs or approved software).

> **Pro Tip:** When running broad timeline queries (like RDP tracking), adjust your timeframe carefully to avoid search timeouts.

---

## 🤝 Contributing

Contributions are heavily encouraged! If you have developed a useful Falcon LogScale query, please consider sharing it with the community.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/New-Query-Name`).
3. Add your query as a `.md` file. **Please use the existing comment headers structure** (Author, Description, MITRE Mapping, False Positives, etc.) for consistency.
4. Commit your changes (`git commit -m 'Add new query for [Threat]'`).
5. Push to the branch (`git push origin feature/New-Query-Name`).
6. Open a Pull Request.

---

## ⚖️ Disclaimer

The queries in this repository are provided "as is" for educational and defensive purposes. They are designed to aid security practitioners in identifying potential threats within their environments. 

* **Test Before Implementing:** Always test and tune queries in a limited scope before converting them into automated scheduled searches or custom IOAs, as aggressive queries can consume significant compute resources or generate excessive false positives.
* The author(s) are not responsible for any impact on system performance or missed detections.
