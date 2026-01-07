//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: PRIVILEGED LOCAL LOGON MONITORING (WORKSTATIONS)
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 1.1
// Author: Cybersecurity Operations
// Last Updated: 2025-12-17
//
// DESCRIPTION:
//   Monitors for successful interactive (LogonType 2) and remote interactive (LogonType 10) 
//   logins performed by local administrators on workstation assets. This query is designed 
//   to surface high-risk access patterns and potential lateral movement across the fleet.
//
// VULNERABILITY DETAILS:
//   Threat: Credential Abuse / Lateral Movement
//   Type: Privilege Escalation
//   Status: OPERATIONAL MONITORING
//   Risk Score: 7.5 (High)
//
// EXPLOITATION REQUIREMENTS:
//   - Attacker possesses valid local administrator credentials.
//   - Network visibility to target workstations (for RDP/LogonType 10).
//   - Target systems must have interactive login capabilities enabled.
//
// USE CASES:
//   - Identify unauthorized RDP sessions using local administrative accounts.
//   - Detect "Pass-the-Hash" or credential stuffing targeting local accounts.
//   - Audit technician activity to ensure compliance with least-privilege policies.
//
// MITRE ATT&CK MAPPING:
//   Technique: T1078.003 - Valid Accounts: Local Accounts
//   Technique: T1021.001 - Remote Services: Remote Desktop Protocol
//   Tactics: Privilege Escalation, Lateral Movement, Persistence
//
// DATA SOURCE:
//   Event Type: UserLogon, aidmaster
//   Required Fields: UserIsAdmin, LogonType, ProductType, UserSid, aid
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows Workstations (ProductType 1)
//
// FALSE POSITIVES:
//   - Legitimate IT support activities using local admin accounts for troubleshooting.
//   - Automated deployment tools or backup agents that trigger administrative flags.
//   - Security scanning software performing authenticated local checks.
//
// INVESTIGATION NOTES:
//   1. Verify if the 'UserName' belongs to an authorized technician or a known service.
//   2. Examine 'SystemsAccessed' count; a high number of unique systems by a single 
//      local admin account often indicates automated lateral movement or credential stuffing.
//   3. Correlate with 'LogonTime'—are these logins occurring outside of standard business hours?
//   4. Review the source IP if available to determine if the connection originated internally.
//
// TUNING RECOMMENDATIONS:
//   - Exclude specific Service Accounts (e.g., 'SYSTEM', 'LOCAL SERVICE') if they trigger UserIsAdmin.
//   - Filter out known-good management subnets or jump box IPs to reduce noise.
//
// REMEDIATION:
//   Priority: MEDIUM-HIGH
//   Action: Rotate credentials for identified local accounts. 
//   Strategy: Deploy Windows Local Administrator Password Solution (LAPS) to ensure 
//             unique, rotated passwords across the workstation environment.
//
// LOGIC EXPLANATION:
//   1. Initial filter targets 'UserLogon' events where the administrative flag is set.
//   2. Filters for LogonType 2 (Interactive) and 10 (RemoteInteractive) to focus on human activity.
//   3. Joins with 'aidmaster' to isolate 'ProductType=1' (Workstations) from servers.
//   4. Enriches decimal values into human-readable strings using Falcon helpers.
//   5. Aggregates data by UserSid to quantify the scope of activity per account.
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════

// Get all user logon events for local admins
#event_simpleName=UserLogon UserIsAdmin=1

// Only get Type 2 and 10 to cull out service accounts
| in(field="LogonType", values=[2, 10])

// Add in ProductType field to distinguish Workstations from Servers
| join({#data_source_name=aidmaster}, field=aid, include=ProductType, mode=left)

// Only show results for workstations (ProductType=1)
| ProductType=1

// Convert decimal values to human readable strings
| $falcon/helper:enrich(field=UserIsAdmin)
| $falcon/helper:enrich(field=LogonType)
| $falcon/helper:enrich(field=ProductType)

// Aggregate results with logon counts to identify the scope of the account usage
| groupBy([UserSid, UserName], function=([
    count(aid, distinct=true, as=SystemsAccessed),
    count(aid, as=TotalLogons),
    collect([ComputerName, UserIsAdmin, LogonType])
]))
| sort(SystemsAccessed, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// 1. FREQUENCY ANALYSIS: Find the most active accounts to identify potential outliers:
// | head(10)
//
// 2. TIME WINDOW: Use bucket to track admin login trends over a specific duration:
// | bucket(1d, field=@timestamp)
//
// 3. ALERTING THRESHOLD: Filter for high-volume access to trigger high-severity alerts:
// | SystemsAccessed > 5
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
