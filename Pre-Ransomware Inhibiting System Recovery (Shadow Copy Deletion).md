//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: Pre-Ransomware Inhibiting System Recovery (Shadow Copy Deletion)
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 1.1 (Improved Timestamp & Logic Expansion)
// Author: Cybersecurity Operations
// Last Updated: 2025-10-20
//
// DESCRIPTION:
//   Identifies the abuse of native Windows administrative utilities (vssadmin, wmic, bcdedit, wbadmin) 
//   to delete Volume Shadow Copies or modify boot configuration data. This behavior is a critical 
//   pre-encryption phase for ransomware groups like DragonForce and LockBit to ensure data 
//   cannot be restored locally after the impact phase.
//
// VULNERABILITY DETAILS:
//   Threat: System Recovery Sabotage
//   Type: Impact / Defense Evasion
//   Status: CRITICAL (Commonly precedes environment-wide encryption)
//   Risk Score: 9.5 (Critical)
//
// EXPLOITATION REQUIREMENTS:
//   - Local Administrative or NT AUTHORITY\SYSTEM privileges.
//   - Execution of built-in Windows binary (LoLBins).
//
// USE CASES:
//   - Detection of active ransomware deployment in the "Inhibit System Recovery" phase.
//   - Identifying unauthorized administrative attempts to purge backup data.
//   - Monitoring for modifications to the Boot Configuration Database (BCD).
//
// MITRE ATT&CK MAPPING:
//   Technique: T1490 - Inhibit System Recovery
//   Sub-Technique: T1059.003 - Command and Scripting Interpreter: Windows Command Shell
//   Tactics: Impact
//
// DATA SOURCE:
//   Event Type: ProcessRollup2
//   Required Fields: FileName, CommandLine, ComputerName, UserName, @timestamp
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows 7 through Windows 11
//   - Windows Server 2008 R2 through Windows Server 2025
//
// FALSE POSITIVES:
//   - Legitimate backup software maintenance cycles (e.g., Veeam, Commvault).
//   - Planned system decommissioning scripts.
//   - Extreme disk space remediation scripts (rare, but possible).
//
// INVESTIGATION NOTES:
//   1. IMMEDIATE: Check for concurrent "File Write" spikes or mass renaming events on the host.
//   2. Review the 'ParentBaseFileName'. If the parent is a script (powershell.exe) or an 
//      unrecognized binary, escalate to High/Critical.
//   3. Correlate with 'UserIdentity'—is this a domain admin account or a service account?
//   4. Check for 'NetworkConnect' events to suspicious IPs from the same host in the last 60 minutes.
//
// TUNING RECOMMENDATIONS:
//   - Exclude specific Service Accounts used by verified backup solutions.
//   - Filter by 'ParentBaseFileName' if your backup agent initiates these calls via a specific binary.
//
// REMEDIATION:
//   Priority: CRITICAL
//   Action: Isolate the host immediately via Falcon Network Containment.
//   Recovery: Initiate incident response protocol to identify the entry point (RDP, Phishing, etc.).
//
// QUERY LOGIC:
//   1. Scope to 'ProcessRollup2' events.
//   2. Filter for specific binaries known for recovery inhibition (vssadmin, wmic, bcdedit, wbadmin).
//   3. Apply regex to find high-intent flags (e.g., 'delete shadows', 'recoveryenabled No').
//   4. Transform the timestamp for analyst readability and display results in descending order.
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName = "ProcessRollup2"
| in(field="FileName", values=["vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe"])
| CommandLine=/(delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+No|safeboot\s+minimal)/i
// Convert the raw epoch timestamp to a readable string
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, as="DetectionTime")
// Display critical metadata for rapid triage
| table([DetectionTime, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, CID])
| sort(DetectionTime, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Join with User Logons to see if the user performed a suspicious login recently:
// | join(query={ #event_simpleName=UserLogon | LogonType=10 }, field=UserSid, include=[RemoteIP])
//
// Broaden search to include PowerShell equivalents (e.g., Check-point/Shadow-copy):
// | CommandLine=/Remove-WmiObject.*Win32_ShadowCopy/i
//
// Monitor for RDP-related parent processes to identify lateral movement:
// | ParentBaseFileName = "rdpclip.exe" OR ParentBaseFileName = "taskhostw.exe"
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
