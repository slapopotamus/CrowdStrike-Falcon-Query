//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: Interactive User Logon Tracking 
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.0
// Author: Cybersecurity Operations
// Last Updated: 2026-01-07
//
// DESCRIPTION:
//   Identifies and aggregates interactive (local) and remote interactive (RDP) logon events across the fleet. 
//   This query is designed to map users to assets and identify the most recent activity per system to 
//   establish a baseline of "normal" user-to-machine affinity and detect stale or unauthorized sessions.
//
// VULNERABILITY DETAILS:
//   CVE: N/A (General Hygiene / Lateral Movement Detection)
//   Type: Credential Access / Lateral Movement
//   Status: OPERATIONAL MONITORING
//
// EXPLOITATION REQUIREMENTS:
//   - Valid credentials or session hijacking capabilities
//   - Network connectivity for Remote Interactive (Type 10) sessions
//   - Local access for Interactive (Type 2) sessions
//
// USE CASES:
//   - Identify the primary user of a specific workstation
//   - Detect lateral movement via RDP (LogonType 10)
//   - Audit administrative logons to sensitive servers
//   - Map UserSids to ComputerNames for incident scoping
//
// MITRE ATT&CK MAPPING:
//   Technique: T1078 - Valid Accounts
//   Sub-Technique: T1078.002 - Domain Accounts
//   Tactics: Lateral Movement, Persistence
//
// DATA SOURCE:
//   Event Type: UserLogon
//   Required Fields: ComputerName, UserName, LogonType, UserSid, @timestamp
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows Workstations (LogonType 2, 10)
//   - Windows Servers (LogonType 2, 10)
//
// FALSE POSITIVES:
//   - Maintenance windows involving heavy administrative RDP use
//   - Automated deployment tools using interactive service accounts
//   - Public kiosks or shared workstations with high user turnover
//
// INVESTIGATION NOTES:
//   1. Verify if the UserName is authorized to log into the specific ComputerName.
//   2. Cross-reference LogonType 10 with source IP addresses to identify unexpected RDP origins.
//   3. Check for "impossible travel" (same user logging in from geographically distant systems).
//   4. Examine the 'LastUsed' field to identify accounts that have been dormant but suddenly active.
//
// TUNING RECOMMENDATIONS:
//   - Filter out known Service Accounts or "Break Glass" accounts to reduce noise.
//   - Add a 'where' clause to exclude standard IT support Jump Boxes if necessary.
//   - Increase the time range to 30+ days for a more accurate asset-user mapping.
//
// REMEDIATION:
//   - Implement Multi-Factor Authentication (MFA) for all Type 10 logons.
//   - Enforce the Principle of Least Privilege (PoLP) regarding RDP permissions.
//   - Disable local admin rights for standard user accounts.
//
// QUERY LOGIC:
//   1. Filters for the 'UserLogon' event type (indexed field for performance).
//   2. Includes optional filters for specific system or user scoping.
//   3. Restricts results to Interactive (2) and Remote Interactive (10) sessions.
//   4. Aggregates data to find the maximum timestamp and unique SIDs per user/host.
//   5. Formats the raw timestamp into a human-readable string.
//
// REFERENCES:
//   - https://attack.mitre.org/techniques/T1078/
//   - https://crowdstrike.com/blog/tech-center/logscale-query-language-tips/
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

// 1. Performance: Start with the indexed tag
#event_simpleName = UserLogon

// 2. PLACEHOLDERS: Uncomment (remove //) and edit to filter
// | ComputerName = /YOUR_COMPUTER_NAME/i
// | UserName = /YOUR_USER_NAME/i

// 3. Filter for Interactive (2) or Remote Interactive (10) logons
| LogonType = /2|10/

// 4. Group by system and user to find the last time they were seen
| groupBy([ComputerName, UserName], function=[max(@timestamp, as=LastUsed), collect(UserSid)])

// 5. Convert the timestamp to a human-readable format
| formatTime("%Y-%m-%d %H:%M:%S", field=LastUsed, as=ReadableLastUsed)

// 6. Output to a clean table
| table([ComputerName, UserName, UserSid, ReadableLastUsed])

// 7. Sort by most recent activity
| sort(LastUsed, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add Source Network Attribution (identify where RDP is coming from):
// | join(query={ #event_simpleName=NetworkConnectIP | remote_port=3389 }, field=ComputerName, include=[RemoteAddressIP4], optional=true)
//
// Identify "First Seen" logons (detect new account activity):
// | groupBy([ComputerName, UserName], function=[
//     min(@timestamp, as=FirstSeen),
//     max(@timestamp, as=LastSeen),
//     count(as=TotalLogons)
//   ])
// | eval(IsNewAccount = if(FirstSeen > (now() - 24h), "YES", "NO"))
//
// Correlate with Process Execution (what did they do after logging in?):
// | join(query={ #event_simpleName=ProcessRollup2 }, field=[ComputerName, UserName], start=-5m, end=+1h)
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
