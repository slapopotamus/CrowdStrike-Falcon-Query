//══════════════════════════════════════════════════════════════════════════════════════════════════
// Post-Access Enumeration Commands - Suspicious Staging Activity
//══════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.0
// Author: Cybersecurity Operations
// Last Updated: 2026-04-20
//
// DESCRIPTION:
// Identifies common hands-on-keyboard Windows enumeration commands often seen during
// early post-access staging. This hunt looks for `whoami /priv`, `cmdkey /list`,
// and `net group`, which can indicate an operator validating privileges, checking
// stored credentials, or enumerating group membership before additional actions.
//
// THREAT CONTEXT:
// Risk Level: Medium
// Status: HUNT / CONTEXTUAL DETECTION
// Note: These commands are common in legitimate administration, so this query is
// best used for correlation, scoping, and analyst review rather than standalone alerting.
//
// USE CASES:
// - Hunt for interactive post-compromise staging activity.
// - Support investigation of exploitation, privilege escalation, or defense evasion.
// - Add context to incidents involving suspicious operator-driven commands.
//
// MITRE ATT&CK MAPPING:
// - T1033: System Owner/User Discovery
// - T1069: Permission Groups Discovery
// - T1087: Account Discovery
//
// DATA SOURCE:
// Event Type: ProcessRollup2
// Required Fields: FileName, CommandLine, ParentBaseFileName, UserName, ComputerName
// Sensor: CrowdStrike Falcon EDR
//
// FALSE POSITIVES:
// - Helpdesk or sysadmin troubleshooting.
// - Administrative scripts or software inventory checks.
// - Internal security testing or red team activity.
//
// INVESTIGATION NOTES:
// 1. Review the parent process and whether execution appears interactive.
// 2. Check whether multiple enumeration commands occurred on the same host/user in a short window.
// 3. Correlate with Defender tampering, credential access, lateral movement, or exploit activity.
//
//══════════════════════════════════════════════════════════════════════════════════════════════════

event_platform=Win
| #event_simpleName=ProcessRollup2
| case {
    FileName=/^whoami\.exe$/i and CommandLine=/\s\/priv\b/i | stage:="enum-whoami-priv";
    FileName=/^cmdkey\.exe$/i and CommandLine=/\s\/list\b/i | stage:="enum-cmdkey-list";
    FileName=/^net1?\.exe$/i and CommandLine=/\bgroup\b/i | stage:="enum-net-group"
  }
| table([@timestamp, stage, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=200)
