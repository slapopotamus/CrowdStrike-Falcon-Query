//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Entra ID / OAuth2 Authorization Code Interception Detection
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 1.0
// Author: Cybersecurity Operations
// Last Updated: 2026-03-05
//
// DESCRIPTION:
//   Detects potential OAuth2 "Authorization Code Interception" or "PKCE Bypass" attempts by monitoring 
//   process execution command lines for specific authentication patterns. This query identifies 
//   processes launched with "prompt=none" parameters—often used in silent token acquisition—and 
//   extracts the primary host and redirect URIs to identify anomalous or non-corporate domains 
//   facilitating token theft.
//
// VULNERABILITY DETAILS:
//   CVE: N/A (General Use-Case / Tactic)
//   Type: Token Theft / Adversary-in-the-Middle (AiTM)
//   Status: ACTIVE EXPLOITATION OBSERVED
//   Mechanism: Attackers use illicit consent grants or malicious apps to intercept authorization 
//              codes. By forcing "prompt=none", they attempt to refresh or gain tokens silently.
//
// EXPLOITATION REQUIREMENTS:
//   - Local or Remote execution context to trigger browser/process events.
//   - Victim must have an active session with the Identity Provider (IdP).
//   - Malicious Redirect URI configured in a compromised or attacker-controlled app.
//
// USE CASES:
//   - Detect "Illicit Consent Grant" follow-on activity.
//   - Identify unauthorized applications requesting silent tokens.
//   - Track compromised accounts used in automated OAuth2 workflows.
//   - Correlate suspicious command-line URLs with known phishing infrastructure.
//
// MITRE ATT&CK MAPPING:
//   Technique: T1528 - Steal Application Access Token
//   Sub-Technique: T1550.001 - Use Alternate Authentication Material: Application Access Token
//   Tactics: Credential Access, Lateral Movement
//
// DATA SOURCE:
//   Event Type: ProcessRollup2
//   Required Fields: CommandLine, ComputerName, UserName, @timestamp
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows Workstations (Browser-based SSO environments)
//   - macOS Endpoints using Enterprise Connect / Jamf Connect
//   - Linux Servers with CLI-based cloud management tools (Azure CLI, AWS CLI)
//
// FALSE POSITIVES:
//   - Legitimate background update services (e.g., Microsoft Edge/Chrome updates).
//   - Internal DevOps scripts using Service Principals or Managed Identities.
//   - Enterprise SSO "keep-alive" mechanisms.
//   - Known-good Redirect URIs (e.g., localhost for developer tools).
//
// INVESTIGATION NOTES:
//   1. IMMEDIATE: Inspect the 'target_domain'. Is it a known Microsoft, Okta, or internal domain?
//   2. Review the 'CommandLine' samples. Look for 'client_id' values that don't match authorized apps.
//   3. Check if the 'UserName' correlates with high-privilege accounts (Global Admin, etc.).
//   4. Pivot to 'UserLogon' events to see if the activity originated from a suspicious IP address.
//   5. Verify if the 'ProcessRollup2' parent process is a browser or a standalone executable.
//
// TUNING RECOMMENDATIONS:
//   - Filter out known corporate redirect domains (e.g., company.com, microsoftonline.com).
//   - Add a whitelist for specific 'client_id' strings known to be used by internal tooling.
//   - Increase the 'hits' threshold for high-volume service accounts.
//
// REMEDIATION:
//   - Revoke the suspicious OAuth2 Refresh Token/Grant in the Entra ID portal.
//   - Enable Conditional Access policies requiring MFA for all token requests.
//   - Reset the password for the affected user and clear active sessions.
//
// QUERY LOGIC:
//   1. Filter for process executions containing 'prompt=none'.
//   2. Use Regex to strip the primary host from the URL string.
//   3. Decode and extract nested Redirect URIs to find the final destination of the token.
//   4. Use 'coalesce' to prioritize the Redirect Host for investigation.
//   5. Aggregate by user and computer to find clusters of suspicious activity.
//
// REFERENCES:
//   - https://attack.mitre.org/techniques/T1528/
//   - https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
//   - https://www.crowdstrike.com/blog/observations-from-the-front-lines-of-threat-hunting/
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

// 1. Tag filter first for maximum performance
#event_simpleName = ProcessRollup2

// 2. Filter ONLY for prompt=none so we don't accidentally drop your test events
| CommandLine = /prompt=none/i 

// 3. Extract the primary domain directly from the command line URL
| regex("(?i)https?://(?<primary_host>[^/ \"']+)", field=CommandLine, strict=false)

// 4. OPTIONALLY extract the redirect URI if it exists in the string
| regex("(?i)redirect_uri=(?<redirect_uri>[^& \"]+)", field=CommandLine, strict=false)
| redirect_uri_decoded := urldecode(redirect_uri)
| regex("(?i)https?://(?<redirect_host>[^/ \"']+)", field=redirect_uri_decoded, strict=false)

// 5. Combine them: Use the redirect_host if it exists; otherwise, use the primary_host
| target_domain := coalesce([redirect_host, primary_host])

// 6. Aggregate results using the unified target_domain
| groupBy([ComputerName, UserName, target_domain], 
    function=[
        count(as=hits), 
        min(@timestamp, as=first_seen), 
        max(@timestamp, as=last_seen), 
        collect(CommandLine, limit=3)
    ])
| sort(hits, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add domain reputation checking (Requires external threat intel integration):
// | ioc_lookup(target_domain, type=domain)
// | filter(confidence > 80)
//
// Correlate with unexpected parent processes (e.g., cmd.exe spawning a browser with these flags):
// | join(query={ #event_simpleName=ProcessRollup2 }, field=ParentProcessId, include=[ImageFileName])
// | filter(ImageFileName != /chrome\.exe|msedge\.exe|firefox\.exe/i)
//
// Detect high-frequency polling (potential automated exfiltration):
// | bucket(@timestamp, span=10m, as=time_bucket)
// | groupBy([UserName, time_bucket], function=count(as=burst_count))
// | filter(burst_count > 50)
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
