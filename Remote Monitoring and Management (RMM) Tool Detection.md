//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: Remote Monitoring and Management (RMM) Tool Detection
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 1.2
// Author: Cybersecurity Operations
// Last Updated: 2025-12-31
//
// DESCRIPTION:
//   Identifies network resolution requests (DNS) associated with common Remote Monitoring and Management (RMM)
//   tools and remote desktop software. While often legitimate, these tools are frequently abused by
//   threat actors for persistence, data exfiltration, and lateral movement (Living off the Land).
//   The query aggregates activity by domain to identify low-prevalence (rare) tools across the fleet.
//
// VULNERABILITY DETAILS:
//   CVE: N/A (Tool Misuse/Living off the Land)
//   Type: Unauthorized Access / Persistence / Command & Control (C2)
//   Status: ONGOING ABUSE IN THE WILD
//   Risk: High - RMM tools often bypass traditional AV/EDR by using signed binaries and legitimate infrastructure.
//
// EXPLOITATION REQUIREMENTS:
//   - Network egress allowed to RMM provider infrastructure.
//   - Ability to execute or install RMM binaries (User or Admin context).
//   - Often used in Ransomware-as-a-Service (RaaS) playbooks post-initial access.
//
// USE CASES:
//   - Detect Shadow IT or unauthorized support tools.
//   - Identify potential Command & Control (C2) activity using legitimate software.
//   - Discover "Low and Slow" data exfiltration channels.
//   - Map RMM tool footprint across the enterprise for policy enforcement.
//
// MITRE ATT&CK MAPPING:
//   Technique: T1219 - Remote Access Software
//   Tactics: Command and Control, Persistence
//
// DATA SOURCE:
//   Event Type: DnsRequest
//   Required Fields: DomainName, ContextBaseFileName, aid
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows, macOS, Linux (Cross-platform RMM support)
//
// FALSE POSITIVES:
//   - Authorized IT Support/Helpdesk operations.
//
// INVESTIGATION NOTES:
//   1. Identify the 'ContextBaseFileName' to see which process triggered the DNS request.
//   2. Cross-reference the 'aid' (Host ID) with authorized support staff or specific departments.
//   3. Check for 'ProcessRollup2' events around the same timeframe to identify the parent process.
//   4. Look for unusual command-line arguments (e.g., --silent, --install) associated with the RMM binary.
//   5. Verify if the domain resolution is persistent or a one-time occurrence.
//   6. Compare the 'HostCount'—RMM tools appearing on only 1-2 hosts are higher priority than enterprise-wide tools.
//
// TUNING RECOMMENDATIONS:
//   - Filter out known-authorized domains used by your corporate Helpdesk.
//   - Add a threshold filter (e.g., | HostCount < 5) to focus on rare/suspicious installations.
//   - Join with 'ManagedApp' inventory to see if the software is managed by SCCM/Intune.
//
// REMEDIATION:
//   - Priority: MEDIUM (Unless associated with an active incident).
//   - Action: Terminate unauthorized processes and uninstall non-sanctioned RMM clients.
//   - Policy: Implement Application Control (AppLocker/Falcon Fusion) to block unauthorized RMM binaries.
//
// QUERY LOGIC:
//   1. Filters for 'DnsRequest' events containing a regex list of known RMM/Remote Access domains.
//   2. Groups results by 'DomainName' to consolidate the view.
//   3. Collects the initiating filenames to determine the source binary.
//   4. Calculates a distinct count of hosts ('aid') to identify the tool's prevalence.
//   5. Sorts by 'HostCount' ascending to surface the most unique (and potentially suspicious) instances.
//
// REFERENCES:
//   - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
//   - https://attack.mitre.org/techniques/T1219/
//   - https://www.crowdstrike.com/blog/identifying-unauthorized-rmm-tools/
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName=DnsRequest
| DomainName=/anydesk\.com|action1\.com|beamyourscreen\.com|snapview\.de|rustdesk\.com|fleetdeck\.io|tailscale\.com|dwservice\.net|secure\.logmein\.com|teamviewer\.com|screenconnect\.com|fixme\.it|n-able\.com|domotz\.com|datto\.com|level\.io|itarian\.com|pulseway\.com|zoho\.com|manageengine\.com|bomgarcloud\.com|bomgar\.com|zabbix\.com/i
| groupBy([DomainName], function=[collect(ContextBaseFileName), count(aid, distinct=true, as=HostCount)])
| sort(HostCount, order=asc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add time-based analysis (Identify spikes in RMM usage):
// | bucket(@timestamp, span=1d, as=detection_day)
// | groupBy([detection_day, DomainName], function=count(aid, distinct=true, as=DailyHostCount))
//
// Correlate with Network Listeners (Check for active inbound tunnels):
// | join(query={ #event_simpleName=NetworkListenEvent2 }, field=aid, include=[LocalPort, Protocol])
//
// Filter for rare occurrences only (Focus on anomalies):
// | test(HostCount < 3)
//
// Hunt for specific binary mismatches (RMM tool renamed to hide):
// | test(ContextBaseFileName != /anydesk|teamviewer|logmein|screenconnect/i)
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
