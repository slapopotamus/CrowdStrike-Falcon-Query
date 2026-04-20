//══════════════════════════════════════════════════════════════════════════════
// Suspicious Execution from User-Writable Directories
//══════════════════════════════════════════════════════════════════════════════
// Version: 1.0
// Author: Cybersecurity Operations
// Last Updated: 2026-04-20
//
// DESCRIPTION:
// Identifies executable files (.exe) launching from high-risk user directories 
// such as "Downloads" and "Pictures". Threat actors frequently land payloads in 
// these folders via phishing or web drive-by downloads. This query provides
// visibility into user-space execution, often a precursor to malware infection,
// ransomware staging, or LOLBin abuse.
//
// VULNERABILITY/THREAT DETAILS:
// Type: Behavioral Indicator (Persistence/Execution)
// Severity: Medium (High in production environments with strict application control)
// Threat Focus: Initial Access, Defense Evasion, Execution
//
// MITRE ATT&CK MAPPING:
// Technique: T1204.002 - User Execution: Malicious File
// Technique: T1059 - Command and Scripting Interpreter
// Technique: T1566 - Phishing
// Tactics: Execution, Defense Evasion, Initial Access
//
// DATA SOURCE:
// Event Type: ProcessRollup2
// Required Fields: ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData
// Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
// All Windows-based endpoints (Workstations/Laptops)
//
// FALSE POSITIVES:
// - Legitimate software installers (e.g., Zoom, Slack, Chrome)
// - User-initiated scripts or portable administrative tools
// - Software packaging/distribution tools running in user context
//
// INVESTIGATION NOTES:
// 1. IMMEDIATE: Check SHA256 hash against threat intel feeds (e.g., VirusTotal).
// 2. Review 'ParentBaseFileName' to determine if the process was launched by 
//    a browser (e.g., chrome.exe, edge.exe) or shell (cmd.exe, powershell.exe).
// 3. Inspect 'CommandLine' for encoded arguments or obfuscated flags.
// 4. Check for network connections initiated by the process.
// 5. Determine if the file has been signed by a trusted vendor.
//
// TUNING RECOMMENDATIONS:
// - Whitelist known-good installers by SHA256 or certificate.
// - Filter out automated internal IT tools if identified by parent process or path.
// - Transition to a "High" severity alert by correlating with network activity.
//
// REMEDIATION:
// - If malicious: Quarantine the host, kill the process, delete the file,
//   and initiate a credential reset for the affected user.
// - Review email/web gateway logs to identify the initial delivery vector.
//
// QUERY LOGIC:
// 1. Filter specifically for ProcessRollup2 events on Windows platforms.
// 2. Regex filter for .exe extensions within \Users\[User]\Downloads or \Pictures paths.
// 3. Project key metadata (Computer, User, Hash, Command) for analyst review.
// 4. Limit results to prevent ingestion overflow during noise.
//
//══════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add hash reputation check (requires Threat Graph lookup):
// | lookup local_file_reputation(field=SHA256HashData, output=score)
// | filter score > 60
//
// Add network correlation (Hunt for post-infection callback):
// | join(query={
//     #event_simpleName=NetworkConnectIPv4
//     | filter RemotePort != 443
// }, field=aid, include=[RemoteAddressIP4, RemotePort])
//
//══════════════════════════════════════════════════════════════════════════════

event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\Users\\[^\\]+\\(Downloads|Pictures)\\[^\\]+\.exe$/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=200)

//══════════════════════════════════════════════════════════════════════════════
