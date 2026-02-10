//══════════════════════════════════════════════════════════════════════════════════════════════════
// Lotus Blossom - Chrysalis APT - Campaign Indicator Detection
//══════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 2.0
// Author: Cybersecurity Operations
// Last Updated: 2026-02-09
//
// DESCRIPTION:
// Detects multi-stage activity associated with the Lotus Blossom (Chrysalis) APT group.
// This query identifies malicious file hashes (at execution AND file-write), command-and-control
// infrastructure (IPs and Domains as separate detection types), registry persistence mechanisms
// disguised as "Bluetooth" services, and execution from suspicious file paths typical of
// the Elknot or Emissary payloads.
//
// CHANGELOG (v2.0):
//   - Fixed: RegistryValueData → RegStringValue (validated against live telemetry)
//   - Fixed: IP regex anchored with ^...$ to prevent partial matches
//   - Added: NewExecutableWritten event for pre-execution hash detection
//   - Added: Split C2 branch into separate IP vs DNS detection types
//   - Added: ContextBaseFileName for DNS events (shows requesting process)
//   - Added: IoCSummary field for quick analyst triage
//   - Removed: Unnecessary leading .* in file path regex
//   - Optimized: Field selection for ad-hoc threat hunting workflow
//
// VULNERABILITY DETAILS:
//   Threat Actor: Lotus Blossom (Chrysalis)
//   Malware Families: Elknot, Emissary, SndSrvc
//   Type: Targeted Espionage / Persistent Backdoor
//   Status: ACTIVELY EXPLOITED IN REGIONAL CAMPAIGNS
//
// EXPLOITATION REQUIREMENTS:
//   - Initial access typically via spear-phishing or vulnerability exploitation.
//   - Local execution permissions for persistence installation.
//   - Outbound network access for C2 communication.
//
// USE CASES:
//   - Ad-hoc threat hunt for Chrysalis infiltration or post-exploitation activity.
//   - Identify systems communicating with known Lotus Blossom infrastructure.
//   - Detect malicious files written to disk BEFORE execution.
//   - Track persistence via masqueraded registry keys and system paths.
//   - Correlate hash-based detections with behavioral anomalies.
//
// MITRE ATT&CK MAPPING:
//   T1547.001 - Registry Run Keys / Startup Folder (Persistence)
//   T1071.001 - Application Layer Protocol: Web Protocols (C2)
//   T1036.005 - Masquerading: Match Legitimate Name or Location (Defense Evasion)
//   T1105     - Ingress Tool Transfer (pre-execution file write detection)
//
// DATA SOURCE:
//   Event Types: ProcessRollup2, NewExecutableWritten, NetworkConnectIP4, DnsRequest,
//                AsepValueUpdate, RegGenericValueUpdate
//   Required Fields: ImageFileName, CommandLine, ComputerName, RemoteAddressIP4,
//                    DomainName, SHA256HashData, RegValueName, RegStringValue,
//                    ContextBaseFileName
//   Sensor: CrowdStrike Falcon EDR
//
// FIELD VALIDATION (2026-02-09 against live telemetry):
//   ✅ RemoteAddressIP4    - Confirmed on NetworkConnectIP4
//   ✅ DomainName          - Confirmed on DnsRequest
//   ✅ RegValueName        - Confirmed on AsepValueUpdate/RegGenericValueUpdate
//   ✅ RegStringValue      - Confirmed on AsepValueUpdate/RegGenericValueUpdate
//   ✅ ContextBaseFileName - Confirmed on DnsRequest and NetworkConnectIP4
//   ✅ SHA256HashData      - Standard field on ProcessRollup2/NewExecutableWritten
//
// FALSE POSITIVES:
//   - Legitimate Bluetooth service updates or third-party Bluetooth management software.
//   - Shared hosting IP addresses if C2 infrastructure has rotated.
//   - Legitimate "svchost.exe" activity (validated by path checking).
//
// INVESTIGATION NOTES:
//   1. IMMEDIATE: Isolate any host with a "Chrysalis Malicious Hash" detection.
//   2. Hash hits on NewExecutableWritten = malware landed but may not have executed yet.
//   3. Verify the parent process of suspicious Bluetooth registry updates.
//   4. Inspect "svchost.exe" in /USOShared/ — this is a known decoy path.
//   5. Review DNS requests for subdomains of skycloudcenter[.]com and wiresguard[.]com.
//   6. Check for lateral movement using credentials harvested post-infection.
//   7. DNS hits: check ContextBaseFileName to identify which process made the request.
//
// TUNING RECOMMENDATIONS:
//   - Filter out known-good SHA256 hashes if internal tools use similar naming conventions.
//   - Whitelist corporate Bluetooth management servers if they trigger the registry filter.
//   - If C2 IPs rotate, update the in() list and cross-reference with threat intel feeds.
//   - Correlate with DetectionSummaryEvent for high-confidence alerting.
//
// RECOMMENDED TIME RANGE:
//   Ad-hoc hunt: Last 7 days minimum, Last 30 days for thorough sweep
//
//══════════════════════════════════════════════════════════════════════════════════════════════════

// ─── Stage 1: Indexed tag filter (fastest possible entry point) ─────────────
#event_simpleName = /ProcessRollup2|NewExecutableWritten|NetworkConnectIP4|DnsRequest|AsepValueUpdate|RegGenericValueUpdate/

// ─── Stage 2: Classify each event against Chrysalis/Lotus Blossom IoCs ──────
| case {

    // ── 1. Malicious SHA256 Hashes (Process Execution + File Write) ─────────
    // Matches on ProcessRollup2 (execution) and NewExecutableWritten (pre-execution)
    in(SHA256HashData, values=[
        "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9",
        "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e",
        "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924",
        "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e",
        "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad",
        "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600",
        "f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a",
        "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906",
        "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd",
        "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd",
        "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8",
        "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda",
        "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5",
        "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3",
        "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd",
        "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"
    ])
    | DetectionType := "Chrysalis Malicious Hash"
    | IoCSummary := format("Hash: %s | Process: %s | Event: %s", field=[SHA256HashData, ImageFileName, #event_simpleName]) ;

    // ── 2a. C2 Activity — IP Connections ────────────────────────────────────
    // Anchored regex prevents partial IP matches (e.g., 195.179.213.0)
    RemoteAddressIP4 = /^(95\.179\.213\.0|61\.4\.102\.97|59\.110\.7\.32|124\.222\.137\.114)$/
    | DetectionType := "Chrysalis C2 - IP"
    | IoCSummary := format("C2 IP: %s:%s | Process: %s", field=[RemoteAddressIP4, RemotePort, ContextBaseFileName]) ;

    // ── 2b. C2 Activity — DNS Requests ──────────────────────────────────────
    DomainName = /api\.skycloudcenter\.com|api\.wiresguard\.com/
    | DetectionType := "Chrysalis C2 - DNS"
    | IoCSummary := format("C2 Domain: %s | Resolved: %s | Process: %s", field=[DomainName, IP4Records, ContextBaseFileName]) ;

    // ── 3. Persistence — Registry Run Key Masquerading as Bluetooth ─────────
    // Field name validated: RegStringValue (NOT RegistryValueData)
    RegObjectName = /\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
    AND (RegValueName = /Bluetooth/i or RegStringValue = /.*AppData.*Bluetooth.*/i)
    | DetectionType := "Chrysalis Persistence"
    | IoCSummary := format("RegKey: %s | Value: %s | Data: %s", field=[RegObjectName, RegValueName, RegStringValue]) ;

    // ── 4. Suspicious File Paths — Masqueraded Executables ──────────────────
    // No leading .* needed — CQL regex is unanchored by default
    ImageFileName = /\\(Bluetooth\\BluetoothService\.exe|USOShared\\svchost\.exe)$/i
    | DetectionType := "Chrysalis Suspicious Path"
    | IoCSummary := format("Suspicious Binary: %s | CLI: %s", field=[ImageFileName, CommandLine]) ;

    // ── Default: No match ───────────────────────────────────────────────────
    * | DetectionType := "NoMatch"
}

// ─── Stage 3: Drop non-matching events ──────────────────────────────────────
| DetectionType != "NoMatch"

// ─── Stage 4: Present results for threat hunting ────────────────────────────
| table([
    @timestamp,
    ComputerName,
    DetectionType,
    IoCSummary,
    ImageFileName,
    CommandLine,
    SHA256HashData,
    RemoteAddressIP4,
    RemotePort,
    DomainName,
    ContextBaseFileName,
    IP4Records,
    RegObjectName,
    RegValueName,
    RegStringValue,
    aid
])
| sort(@timestamp, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════
// THREAT HUNT FOLLOW-UP QUERIES
//
// After running the main query, use these to pivot on any hits:
//
// ── Pivot 1: Timeline all activity for a compromised host ───────────────────
// #event_simpleName = /ProcessRollup2|NetworkConnectIP4|DnsRequest|AsepValueUpdate/
// | ComputerName = "COMPROMISED-HOST-NAME"
// | table([@timestamp, #event_simpleName, ImageFileName, CommandLine, RemoteAddressIP4, DomainName])
// | sort(@timestamp, order=asc)
//
// ── Pivot 2: What else did the C2 process do? ───────────────────────────────
// #event_simpleName = /ProcessRollup2|NetworkConnectIP4|DnsRequest/
// | aid = "AGENT_ID_FROM_HIT"
// | ContextProcessId = "PROCESS_ID_FROM_HIT" or TargetProcessId = "PROCESS_ID_FROM_HIT"
// | table([@timestamp, #event_simpleName, ImageFileName, CommandLine, RemoteAddressIP4, DomainName])
// | sort(@timestamp, order=asc)
//
// ── Pivot 3: Lateral movement from compromised host ─────────────────────────
// #event_simpleName = UserLogon
// | LogonType = /3|10/
// | RemoteAddressIP4 = "COMPROMISED_HOST_IP"
// | groupBy([ComputerName, UserName, RemoteAddressIP4], function=count())
//
// ── Pivot 4: Check if hash was written before execution ─────────────────────
// #event_simpleName = /NewExecutableWritten|ProcessRollup2/
// | SHA256HashData = "HASH_FROM_HIT"
// | table([@timestamp, #event_simpleName, ComputerName, ImageFileName, TargetFileName])
// | sort(@timestamp, order=asc)
//
//══════════════════════════════════════════════════════════════════════════════════════════════════
