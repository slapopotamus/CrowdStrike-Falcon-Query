//══════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: PowerShell Encoded Command Deobfuscation and Analysis
//══════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 1.2
// Author: Cybersecurity Operations
// Last Updated: 2025-12-31
//
// DESCRIPTION:
//   Detects and decodes Base64 encoded PowerShell commands executed via the command line.
//   This query identifies common obfuscation techniques used by attackers to bypass legacy
//   logging and security controls. It specifically targets the -EncodedCommand flag (and
//   its aliases) to reveal the underlying script logic for forensic analysis.
//
// VULNERABILITY DETAILS:
//   Vulnerability: Obfuscated PowerShell Execution
//   Type: Defense Evasion / Command and Scripting Interpreter
//   Status: ACTIVE EXPLOITATION OBSERVED
//   Context: Attackers use encoded commands to hide malicious intent, such as credential
//            harvesting, lateral movement scripts, or payload delivery.
//
// EXPLOITATION REQUIREMENTS:
//   - Local or Remote Command Execution (RCE) capability
//   - PowerShell interpreter present on the host
//   - Sufficient privileges to execute specific .NET classes or modules
//
// USE CASES:
//   - Detect potential malware staging via PowerShell
//   - Identify hidden administrative activity or unauthorized scripts
//   - Deobfuscate complex one-liners for rapid incident response triage
//   - Correlate encoded commands with suspicious network connections
//
// MITRE ATT&CK MAPPING:
//   Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
//   Technique: T1027 - Obfuscated Files or Information
//   Tactics: Execution, Defense Evasion
//
// DATA SOURCE:
//   Event Type: ProcessRollup2
//   Required Fields: ImageFileName, CommandLine, ComputerName, aid, @timestamp
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows 10/11 (All Versions)
//   - Windows Server 2016/2019/2022/2025
//
// FALSE POSITIVES:
//   - Legitimate management software (e.g., SCCM, Tanium, Intune) using encoded scripts
//   - Backup and monitoring agents performing system checks
//   - IT administrative automation scripts
//
// INVESTIGATION NOTES:
//   1. Review the 'DecodedString' field to understand the script's actual intent.
//   2. Check if the 'uniqueEndpointCount' is low, indicating targeted activity.
//   3. Correlate 'executionCount' spikes with known maintenance windows.
//   4. Inspect the parent process (ParentBaseFileName) to see what spawned PowerShell.
//   5. Look for subsequent network connections (NetworkConnectIP4) from the same 'aid'.
//
// TUNING RECOMMENDATIONS:
//   - Filter out known-good command line prefixes (e.g., specific MDM paths).
//   - Whitelist specific 'DecodedString' patterns known to be benign in your environment.
//   - Increase 'cmdLength' thresholds to ignore very short, trivial commands.
//
// REMEDIATION:
//   - Priority: MEDIUM (Context Dependent)
//   - Action: Disable PowerShell for non-admin users where possible.
//   - Policy: Enforce PowerShell Constrained Language Mode (CLM) via AppLocker/GPO.
//
// QUERY LOGIC:
//   1. Filter for Windows PowerShell process executions.
//   2. Regex match for common encoded command flags (-e, -enc, -encodedcommand).
//   3. Calculate command length and aggregate by unique endpoints to find outliers.
//   4. Use base64Decode to reveal the hidden script content (UTF-16LE).
//   5. Perform a nested decode check for multi-layered obfuscation.
//
// REFERENCES:
//   - https://attack.mitre.org/techniques/T1027/
//   - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.4#-encodedcommand-base64encodedcommand
//
//══════════════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/\s+\-(e|encoded|encodedcommand|enc)\s+/i
| CommandLine=/\-(?<psEncFlag>(e|encoded|encodedcommand|enc))\s+/i
| length("CommandLine", as="cmdLength")
| groupby([psEncFlag, cmdLength, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")

// Look for encoded messages in the decoded message and decode those too.
| case {
  DecodedString = /encoded/i
  | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
  | SubCmdLinePrefix := splitString(field=EncodedString, by="-EncodedCommand ", index=0)
  | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
  * }
| table([executionCount, uniqueEndpointCount, cmdLength, DecodedString, CommandLine])
| sort(executionCount, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add entropy analysis (detect high-randomness payloads):
// | entropy(field=CommandLine, as=cmd_entropy)
// | filter(cmd_entropy > 4.5)
//
// Correlate with Network Activity:
// | join(query={
//     #event_simpleName=NetworkConnectIP4
//     | select([aid, RemoteIP, RemotePort, @timestamp])
//   }, field=aid, start=-5m, end=+5m, include=[RemoteIP, RemotePort])
//
// Filter for SYSTEM context only:
// | filter(TokenTag_integer=1)
//
//══════════════════════════════════════════════════════════════════════════════════════════════════
