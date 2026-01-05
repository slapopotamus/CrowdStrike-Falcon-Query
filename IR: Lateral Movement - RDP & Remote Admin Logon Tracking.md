//══════════════════════════════════════════════════════════════════════════════════════════
// IR: Lateral Movement - RDP & Remote Admin Logon Tracking
//══════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.1
// Author: Cybersecurity Operations
// Last Updated: 2026-01-05
//
// DESCRIPTION:
//   Identifies Remote Interactive logons (RDP) via the 'UserIdentity' event stream.
//   This query distinguishes between Standard and Administrative accounts to highlight
//   high-risk remote access. It includes a toggleable filter to isolate activity 
//   for specific high-value accounts or compromised users during an active incident.
//
// INVESTIGATION CONTEXT:
//   - Trigger: "Impossible Travel" alert or suspect activity from a specific UserID.
//   - Goal: Map the spread of a compromised account or verify authorized administrative access.
//   - Scope: Remote Desktop Protocol (RDP) sessions (Logon Type 10).
//
// THREAT HUNTING & INCIDENT RESPONSE USE CASES:
//   - Detect "Lateral Movement" where attackers RDP from patient-zero to high-value servers.
//   - Identify compromised "Service Accounts" improperly using interactive RDP logins.
//   - Audit vendor or third-party remote access during off-hours.
//   - Validate "Privilege Escalation" by tracking standard users suddenly logging in as Admins.
//
// MITRE ATT&CK MAPPING:
//   - T1021.001: Remote Services: Remote Desktop Protocol
//   - T1078: Valid Accounts
//   - T1003: OS Credential Dumping (Precursor activity)
//
// DATA SOURCE:
//   Event Type: UserIdentity
//   Required Fields: LogonType, UserIsAdmin, ComputerName, UserName, UserPrincipal
//   Sensor: CrowdStrike Falcon EDR
//
// FALSE POSITIVES:
//   - System Administrators performing scheduled maintenance.
//   - Jump Box / Bastion Host traffic (should follow a predictable pattern).
//   - Automated testing software that utilizes RDP sessions.
//
// INVESTIGATION NOTES:
//   1. 'LogonType=10' confirms an RDP session; distinct from Network logons (Type 3).
//   2. High volume of RDP from a single workstation to many others indicates "One-to-Many" movement.
//   3. Review 'UserPrincipal' to detect Microsoft Accounts (Outlook/Live) vs Domain Accounts.
//
// TUNING RECOMMENDATIONS:
//   - [Active Hunt]: Uncomment the 'UserName' line to focus on a specific suspect (e.g., "admin").
//   - Filter out known IT Admin Jump Boxes: | ComputerName != "IT-JUMP-01"
//   - Focus only on Admin logins for critical alerts: | UserIsAdmin=1
//
// QUERY LOGIC:
//   1. Filter for 'UserIdentity' events specifically matching RDP (LogonType=10).
//   2. Use a 'case' statement to translate 'UserIsAdmin' into human-readable tags.
//   3. [Optional] Filter by specific UserName to isolate a single identity.
//   4. Output a sorted table of the most recent connections first.
//
//══════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName=UserIdentity
| LogonType=10
| case {
    UserIsAdmin=1 | Privileges := "ADMIN";
    UserIsAdmin=0 | Privileges := "Standard";
    * | Privileges := "Unknown";
}
// | UserName = "admin"  // <--- Remove "//" and change name to filter
| table([@timestamp, ComputerName, LocalAddressIP4, UserName, UserPrincipal, LogonDomain, Privileges, LogonServer])
| sort(@timestamp, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Join with UserLogon events to get the Source IP (RDP Client IP):
// | join(query={#event_simpleName=UserLogon}, field=UserSessionId, include=[RemoteAddressIP4 as SourceIP])
//
// Detect RDP sessions initiated by Service Accounts (Naming convention based):
// | UserName matches /(?i)^svc_|^sa_/ 
//
// Visualize the top targets for RDP Movement:
// | groupBy([ComputerName], function=count()) | sort(count, order=desc)
//══════════════════════════════════════════════════════════════════════════════════════════
