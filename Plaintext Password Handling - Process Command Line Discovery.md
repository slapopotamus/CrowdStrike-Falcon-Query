//════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: Plaintext Password Handling - Process Command Line Discovery
//════════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.2
// Author: Cybersecurity Operations
// Last Updated: 2025-12-31
//
// DESCRIPTION:
//   Identifies processes and applications that potentially handle or pass plaintext passwords
//   within command-line arguments. This query targets insecure administrative practices,
//   legacy scripts, and third-party utilities that expose sensitive credentials in process
//   metadata, which can be harvested by local attackers or malware.
//
// VULNERABILITY DETAILS:
//   CVE: N/A (General Insecure Configuration / CWE-522)
//   CVSS: 7.5 (High) - Context Dependent
//   Type: Information Disclosure / Insecure Credential Storage
//   Status: ONGOING OBSERVATION
//   CISA KEV: N/A
//
// EXPLOITATION REQUIREMENTS:
//   - Local authenticated access (to view process lists)
//   - Execution of scripts/binaries with hardcoded credentials
//   - Presence of logging mechanisms that capture command-line strings
//
// USE CASES:
//   - Detect administrative scripts passing 'net use' or 'runas' passwords
//   - Identify legacy backup or database tools using CLI-based auth
//   - Audit environment for credential exposure in process monitoring logs
//   - Support insider threat investigations involving credential harvesting
//
// MITRE ATT&CK MAPPING:
//   Technique: T1552 - Unsecured Credentials
//   Sub-Technique: T1552.003 - Bash History / Command Line Logs
//   Tactics: Credential Access
//
// DATA SOURCE:
//   Event Type: ProcessRollup2
//   Required Fields: FileName, CommandLine, ComputerName, aid
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows Workstations and Servers (All Versions)
//   - Linux/macOS via equivalent process event types
//
// FALSE POSITIVES:
//   - Legitimate security tools performing credential rotations
//   - False matches on command-line flags that look like password strings
//   - Internal automation tools with encrypted blobs mistaken for plaintext
//
// INVESTIGATION NOTES:
//   1. IMMEDIATELY verify if the identified process is a known administrative script.
//   2. Review the full CommandLine string to confirm if the value is a literal password.
//   3. Check the user context (UserName) to see if a privileged account is being exposed.
//   4. Pivot to 'UserLogon' events to see if the exposed account is being used elsewhere.
//   5. Determine if the application supports alternative authentication (Managed Identities, Vaults).
//
// TUNING RECOMMENDATIONS:
//   - Filter out known-safe automation accounts (Service Accounts).
//   - Add specific exclusions for "REDACTED" or masked strings if using 3rd party wrappers.
//   - Increase the host threshold to find rare/unique instances of credential leakage.
//
// REMEDIATION:
//   - Priority: HIGH (Credential exposure often leads to rapid lateral movement).
//   - Action: Transition from CLI-based passwords to Environment Variables or Secret Managers.
//   - Guidance: Implement 'Protected Users' group in AD to mitigate impact of leaked hashes.
//
// QUERY LOGIC:
//   1. Filters for Windows ProcessRollup2 events.
//   2. Searches for specific (redacted) pattern matches in the command line.
//   3. Aggregates findings by FileName to identify the most common "leaky" apps.
//   4. Calculates the distinct count of affected hosts (aid) for impact assessment.
//
// REFERENCES:
//   - https://attack.mitre.org/techniques/T1552/003/
//   - https://cwe.mitre.org/data/definitions/522.html
//════════════════════════════════════════════════════════════════════════════════════════════════════

"#event_simpleName" = ProcessRollup2 event_platform="Win" CommandLine=/REDACTED/
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([FileName], function=[count(aid, distinct=true, as="Hosts")])
| sort(Hosts)

//════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add user context and specific command line samples:
// | groupBy([FileName], function=[
//     count(aid, distinct=true, as=Hosts),
//     collect([CommandLine, UserName], limit=10)
//   ])
//
// Identify the first and last time this behavior was seen per host:
// | groupBy([ComputerName, FileName], function=[
//     selectFromMin(field=@timestamp, as=first_seen),
//     selectFromMax(field=@timestamp, as=last_seen)
//   ])
//
// Correlate with credential dumping attempts (e.g., Mimikatz):
// | join(query={
//     #event_simpleName=ProcessRollup2
//     | ImageFileName=/mimikatz|procdump|pypykatz/
//   }, field=ComputerName, include=[ImageFileName, CommandLine], kind=left)
//
//════════════════════════════════════════════════════════════════════════════════════════════════════
