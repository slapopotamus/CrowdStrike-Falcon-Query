//══════════════════════════════════════════════════════════════════════════════════════════════════
// NTLM Weak Authentication and Key Length Detection
//══════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.0
// Author: Cybersecurity Operations
// Last Updated: 2026-02-04
//
// DESCRIPTION:
// Identifies potentially insecure NTLM authentication attempts within the environment by 
// monitoring for legacy NTLM versions and weak session security (SSP). This query targets 
// authentication events where the key length is below modern standards, facilitating 
// identification of legacy systems or misconfigured protocols susceptible to relay attacks.
//
// VULNERABILITY DETAILS:
//  - CVE: N/A (General Configuration/Protocol Weakness)
//  - Type: Weak Authentication Protocol (NTLMv1/LM)
//  - Status: ACTIVE RISK in legacy environments
//  - Risk: Susceptible to Pass-the-Hash, Relay attacks, and Brute-force.
//
// EXPLOITATION REQUIREMENTS:
//  - Network visibility to authentication traffic.
//  - Presence of legacy clients or servers supporting NTLMv1 or 40/56-bit encryption.
//  - Lack of "NtlmMinClientSec" or "NtlmMinServerSec" enforcement.
//
// USE CASES:
//  - Identify legacy NTLMv1/LM traffic for protocol retirement.
//  - Detect "Man-in-the-Middle" (MitM) downgrades to weak encryption.
//  - Audit compliance with internal encryption standards (Minimum 128-bit).
//  - Surface specific hostnames/users relying on non-SSP authentication.
//
// MITRE ATT&CK MAPPING:
//  - Technique: T1550.002 - Use Alternate Authentication Material: Pass the Hash
//  - Technique: T1557 - Adversary-in-the-Middle
//  - Tactics: Credential Access, Lateral Movement
//
// DATA SOURCE:
//  - Event Type: UserLogon (Windows Event 4624/4625 via LogScale/FLTR)
//  - Required Fields: AuthenticationPackageName, LmPackageName, KeyLength, WorkstationName
//  - Sensor: CrowdStrike Falcon EDR / LogScale Windows Event Logs
//
// AFFECTED SYSTEMS:
//  - Windows Desktop (Legacy and modern if NTLM is not restricted)
//  - Windows Server (Domain Controllers, File Servers)
//  - Non-Windows systems utilizing Samba/SMB legacy stacks.
//
// FALSE POSITIVES:
//  - Legacy industrial control systems (ICS) or medical devices.
//  - Older printer/scanner service accounts.
//  - Internal automated vulnerability scanners performing protocol discovery.
//  - Legacy internal applications hardcoded for NTLMv1.
//
// INVESTIGATION NOTES:
//  1. Correlate "SSP: No" results with Source IP to identify the physical device.
//  2. Verify if the Username is a service account or a human user.
//  3. Check if KeyLength=0 indicates an anonymous logon or a failure to negotiate.
//  4. Prioritize remediation for sessions where KeyLength is 40 or 56-bit.
//
// TUNING RECOMMENDATIONS:
//  - Exclude known-legacy service accounts once documented.
//  - Filter out specific "Hostname" patterns for isolated legacy VLANs.
//  - Add thresholding to alert only if multiple unique users use weak NTLM from one host.
//
// REMEDIATION:
//  - Action: Enforce "Network security: Restrict NTLM: Incoming NTLM traffic" via GPO.
//  - Action: Set "Minimum session security for NTLM" to 128-bit encryption.
//  - Action: Migrate legacy applications to Kerberos authentication.
//
// QUERY LOGIC:
//  1. Filter for NTLM authentication packages while excluding NTLMv2 (focus on legacy).
//  2. Aggregate by Hostname, Username, and KeyLength to find unique pairings.
//  3. Use case logic to label 128-bit as "SSP: Yes" and legacy lengths as "SSP: No".
//  4. Present data in a structured table for rapid assessment of risk surface.
//
// REFERENCES:
//  - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic
//  - https://attack.mitre.org/techniques/T1557/
//  - https://www.crowdstrike.com/blog/stopping-the-ntlm-relay-attack/
//
//══════════════════════════════════════════════════════════════════════════════════════════════════

| windows.EventData.AuthenticationPackageName=NTLM
| windows.EventData.LmPackageName!= "NTLM V2" 
| groupBy([windows.EventData.WorkstationName, user.target.name, windows.EventData.KeyLength])
| rename(field="windows.EventData.WorkstationName", as="Hostname")
| rename(field="user.target.name", as="Username")
| rename(field="windows.EventData.KeyLength", as="KeyLength")
| sort(field=KeyLength, type=number, order=desc)
| case{
    KeyLength = 128 | SSP := "Yes";
    in(field="KeyLength", values=[0, 40, 56]) | SSP := "No"
}
| table([Hostname, Username, KeyLength, SSP])

//══════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add logon type correlation (Identify Network vs. Interactive):
// | join(query={#event_simpleName=UserLogon}, field=Username, include=[LogonType])
//
// Count occurrences to prioritize high-chatter legacy systems:
// | groupBy([Hostname, Username, KeyLength, SSP], function=count(as=TotalAttempts))
// | sort(TotalAttempts, order=desc)
//
// Filter for critical servers only:
// | Hostname=/^DC-.*|^SQL-.*/i
//
//══════════════════════════════════════════════════════════════════════════════════════════════════
