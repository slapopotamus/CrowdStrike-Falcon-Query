//══════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: Certutil Remote Payload Download Detection
//══════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.2
// Author: Cybersecurity Operations
// Last Updated: 2025-12-17
//
// DESCRIPTION:
//   Detects instances of 'certutil.exe' being used to make remote web requests (HTTP/HTTPS).
//   While 'certutil' is a legitimate Windows CLI program for managing certificates, it is
//   frequently abused by attackers (LotL) to download second-stage malware, encoded
//   scripts, or exfiltrate data while bypassing basic perimeter security.
//
// VULNERABILITY DETAILS:
//   CVE: N/A (Feature Abuse)
//   Type: Living off the Land (LotL)
//   Status: Actively used by multiple APT groups (e.g., Lazarus, MuddyWater).
//   CISA KEV: N/A
//
// EXPLOITATION REQUIREMENTS:
//   - Local authenticated access (User context).
//   - Outbound network connectivity to the internet or attacker-controlled C2.
//
// USE CASES:
//   - Detect "certutil -urlcache -split -f" download patterns.
//   - Identify encoded payload retrieval via "-verifyctl".
//   - Correlate suspicious process ancestry (e.g., cmd.exe or powershell.exe spawning certutil).
//
// MITRE ATT&CK MAPPING:
//   Technique: T1105 - Ingress Tool Transfer
//   Sub-Technique: N/A
//   Tactics: Command and Control
//
// DATA SOURCE:
//   Event Type: ProcessRollup2, ProcessBlocked
//   Required Fields: ImageFileName, CommandLine, ComputerName, UserSid, ParentBaseFileName
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - All Windows Desktop and Server versions.
//
// FALSE POSITIVES:
//   - Legitimate certificate revocation list (CRL) updates.
//   - Software installers performing self-updates or verifying signatures.
//   - Domain Controller maintenance tasks.
//
// INVESTIGATION NOTES:
//   1. IMMEDIATE: Inspect the URL in the 'CommandLine'. Is the domain known-good or suspicious?
//   2. Check the download destination (e.g., %TEMP%, \Public\, or \Downloads\).
//   3. Review process ancestry: Was this spawned by a web browser, Office app, or shell?
//   4. Pivot to 'NetworkReceive' events for the same 'TargetProcessId' to see data volume.
//   5. Check for subsequent execution of the downloaded file (e.g., 'ProcessRollup2' for the new file).
//
// TUNING RECOMMENDATIONS:
//   - Filter out known internal CRL URLs (e.g., *.microsoft.com, *.pki.goog).
//   - Exclude specific service accounts used for automated PKI management.
//
// REMEDIATION:
//   Priority: HIGH (if source URL is unknown)
//   Action: Isolate host, terminate the process tree, and retrieve the downloaded file for analysis.
//
// QUERY LOGIC:
//   1. Filters for Windows process starts or blocked executions.
//   2. Targets the certutil binary specifically.
//   3. Regex match for URI schemes (http/https) within the command line arguments.
//   4. Formats for human-readable triage via a structured table.
//
// REFERENCES:
//   - https://attack.mitre.org/techniques/T1105/
//   - https://lolbas-project.github.io/#certutil
//══════════════════════════════════════════════════════════════════════════════════════════════════

in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win
| ImageFileName=/certutil\.exe$/i
| CommandLine=/(https?:)/i

// --- READABILITY IMPROVEMENTS ---
| formatTime(format="%Y-%m-%d %H:%M:%S", field="@timestamp", as="DetectionTime")
| table([DetectionTime, ComputerName, UserSid, ParentBaseFileName, CommandLine])
| sort(DetectionTime, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add Hostname resolution:
// | aid_master(field=[aid])
//
// Resolve SIDs to Usernames:
// | mount(src="user_info", key=UserSid)
//
// Stack by URL to find unique/rare downloads:
// | groupBy([CommandLine], function=count(as=TotalSeen))
// | sort(TotalSeen, order=asc)
//══════════════════════════════════════════════════════════════════════════════════════════════════
