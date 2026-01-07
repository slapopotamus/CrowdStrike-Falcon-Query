//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: Cisco FTD - Enhanced External Threat Analysis & Deny Reason Correlation
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 2.0.2
// Author: Cybersecurity Operations
// Last Updated: 2025-12-04
//
// DESCRIPTION:
//   Performs deep-packet inspection of Cisco Firepower Threat Defense (FTD) logs to identify and
//   classify external attack patterns. This query correlates FTD Message IDs with Deny Reasons
//   to provide context on why traffic was dropped, targeting ingress exploit attempts,
//   brute-force activity, and reconnaissance.
//
// VULNERABILITY DETAILS:
//   Threat Category: External Ingress Attacks
//   Focus: Reconnaissance, Initial Access, and Credential Access
//   Status: ACTIVE MONITORING
//   CISA KEV: Applicable to various perimeter-based exploitation attempts.
//
// EXPLOITATION REQUIREMENTS:
//   - External connectivity to FTD-protected interfaces
//   - Attempted violation of configured Access Control Policies (ACP)
//   - Generation of specific FTD Syslog IDs (106023, 106100, 313001, etc.)
//
// USE CASES:
//   - Identify top external offenders attacking the perimeter
//   - Correlate FTD block reasons (ACL vs. Protocol violation)
//   - Discover internal assets being targeted by specific threat actors
//   - Geographically visualize origin of attack campaigns
//   - Prioritize incident response for high-volume brute force attempts
//
// MITRE ATT&CK MAPPING:
//   Technique: T1595 - Active Scanning
//   Technique: T1110 - Brute Force
//   Technique: T1190 - Exploit Public-Facing Application
//   Tactics: Reconnaissance, Initial Access, Credential Access
//
// DATA SOURCE:
//   Event Type: Cisco FTD Syslog (via LogScale / FLTR)
//   Required Fields: @rawstring, @timestamp
//   Sensor: Cisco Firepower Threat Defense (FTD)
//
// AFFECTED SYSTEMS:
//   - Internal Assets exposed via Static NAT/Port Forwarding
//   - VPN Termination Endpoints
//   - DMZ Infrastructure
//
// FALSE POSITIVES:
//   - Misconfigured internal applications attempting to reach external peers
//   - Authorized external security scanners (Qualys, Nessus, Shodan)
//   - Temporary network routing instability causing TCP reset (denied) events
//
// INVESTIGATION NOTES:
//   1. Review 'ThreatType' to determine if the attack is targeted (Exploit) or opportunistic (Scan).
//   2. Cross-reference 'SrcIP' with Threat Intelligence feeds (CrowdStrike Falcon Intelligence).
//   3. Inspect 'DstIP' to determine if the target is a critical asset or a honeypot.
//   4. Analyze 'DenyReason'—is it a generic ACL drop or a specific inspection engine block?
//   5. Check for successful logins from the same 'SrcIP' in VPN or Application logs.
//
// TUNING RECOMMENDATIONS:
//   - Whitelist known-good external partner IPs to reduce noise.
//   - Adjust 'DenyCount' thresholds for alerting (e.g., >1000 hits/hr).
//   - Filter out common background noise (e.g., NTP/123 or DNS/53 if expected).
//
// REMEDIATION:
//   - Priority: MEDIUM (Active blocking is occurring, but indicates intent).
//   - Action: Implement Shun/Block at the upstream edge for high-frequency offenders.
//   - Action: Verify patched status of internal DstIPs targeted by 'Exploit' patterns.
//
// QUERY LOGIC:
//   1. Filter for specific FTD Deny Message IDs.
//   2. Extract Source/Destination IP, Port, and Deny Reason via Regex.
//   3. Enrich SrcIP with GeoIP data and filter out internal/private IP ranges.
//   4. Classify threat based on destination port (e.g., 3389 -> RDP Brute Force).
//   5. Aggregate and format for SOC dashboarding.
//
// REFERENCES:
//   - https://www.cisco.com/c/en/us/td/docs/security/firepower/syslogs/ftd-syslogs.html
//   - https://attack.mitre.org/techniques/T1110/
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

// Search for FTD denied traffic
"%FTD" AND ("denied" OR "deny" OR "106023" OR "106100" OR "313001" OR "313004" OR "710003")

// Parse FTD message ID (tells us the deny type)
| regex(field=@rawstring, regex="%FTD-\\d-(?<MessageID>\\d+):", strict=false)

// Parse deny reason/description
| regex(field=@rawstring, regex="%FTD-\\d-\\d+:\\s+(?<DenyReason>[^\\n]+)", strict=false)

// Parse source IP from various FTD deny formats
| regex(field=@rawstring, regex="from\\s+(?<SrcIP>[\\d\\.]+)[/:](?<SrcPort>\\d+)", strict=false)
| regex(field=@rawstring, regex="[Dd]eny\\s+(?<Protocol2>\\w+)\\s+src\\s+(?<SrcInterface>[\\w-]+):(?<SrcIP2>[\\d\\.]+)", strict=false)
| regex(field=@rawstring, regex="denied\\s+(?<Protocol3>\\w+)\\s+src\\s+(?<SrcInterface2>[\\w-]+):(?<SrcIP3>[\\d\\.]+)", strict=false)

// Parse destination info (what they're attacking)
| regex(field=@rawstring, regex="dst\\s+(?<DstInterface>[\\w-]+):(?<DstIP>[\\d\\.]+)/(?<DstPort>\\d+)", strict=false)
| regex(field=@rawstring, regex="to\\s+(?<DstInterface2>[\\w-]+):(?<DstIP2>[\\d\\.]+)", strict=false)

// Parse ACL name if present
| regex(field=@rawstring, regex="by ACL\\s+(?<ACL_Name>[\\w-]+)", strict=false)

// Consolidate parsed fields
| SrcIP := coalesce([SrcIP, SrcIP2, SrcIP3])
| Protocol := coalesce([Protocol2, Protocol3])
| DstIP := coalesce([DstIP, DstIP2])
| DstInterface := coalesce([DstInterface, DstInterface2])

// Filter: Only keep events where we parsed a source IP
| SrcIP=*

// FILTER OUT PRIVATE IPs - Only show EXTERNAL/PUBLIC IPs
| SrcIP != /^10\./
| SrcIP != /^172\.(1[6-9]|2[0-9]|3[0-1])\./
| SrcIP != /^192\.168\./
| SrcIP != /^127\./
| SrcIP != /^169\.254\./

// ADD GEOIP ENRICHMENT
| ipLocation(SrcIP)

// CLASSIFY THREAT TYPE based on ports and patterns
| case {
    DstPort=/^(22|2222)$/ | ThreatType := "SSH Brute Force";
    DstPort=/^(3389|3388)$/ | ThreatType := "RDP Brute Force";
    DstPort=/^(445|139|135)$/ | ThreatType := "SMB/Windows Exploit";
    DstPort=/^(1433|3306|5432)$/ | ThreatType := "Database Attack";
    DstPort=/^(80|8080|8000|8888)$/ | ThreatType := "Web Attack";
    DstPort=/^(443|8443)$/ | ThreatType := "HTTPS/Web Attack";
    DstPort=/^(23|21|25)$/ | ThreatType := "Legacy Service Attack";
    MessageID="313001" | ThreatType := "ICMP Scan/Recon";
    Protocol="icmp" | ThreatType := "ICMP Scan/Recon";
    * | ThreatType := "Port Scan/Other";
}

// Group by source IP with detailed context
| groupBy([SrcIP, "SrcIP.country", ThreatType], function=[
    count(as=DenyCount),
    selectLast([DenyReason, MessageID, ACL_Name]),
    collect([DstIP], limit=10),
    collect([DstPort], limit=10),
    collect([Protocol], limit=5),
    collect([DstInterface], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
])

// Convert timestamps to human-readable format
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="America/New_York")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="America/New_York")

| sort(DenyCount, order=desc, limit=25)

| table([
    SrcIP,
    "SrcIP.country",
    ThreatType,
    DenyCount,
    DenyReason,
    MessageID,
    ACL_Name,
    DstIP,
    DstPort,
    Protocol,
    DstInterface,
    FirstSeen,
    LastSeen
])

//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add time-based bucketing to identify surge in attack volume:
// | bucket(@timestamp, span=1h, as=attack_window)
// | groupBy([attack_window, ThreatType], function=count())
//
// Correlate with CrowdStrike Threat Intel for known malicious actors:
// | join(query={#type=ThreatIntel | threat_actor=*}, field=SrcIP, include=[threat_actor, confidence])
//
// Hunt for internal-to-external "Deny" indicating possible C2/Exfiltration:
// | filter(SrcIP = /^10\./ OR SrcIP = /^192\.168\./)
// | filter(DstIP != /^10\./ AND DstIP != /^192\.168\./)
//══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
