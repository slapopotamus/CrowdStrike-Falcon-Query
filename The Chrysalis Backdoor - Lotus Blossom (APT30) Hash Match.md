//══════════════════════════════════════════════════════════════════════════════════════════════════
// The Chrysalis Backdoor - Lotus Blossom (APT30) Hash Match
//══════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 1.0
// AUTHOR: Cybersecurity Operations
// Last Updated: 2026-02-03
//
// DESCRIPTION:
// Detects process execution events associated with the Chrysalis Backdoor, a modular toolkit 
// attributed to the Lotus Blossom (APT30) threat actor. This query identifies specific 
// malicious binaries and DLL side-loading payloads used for persistent access and 
// data exfiltration within target environments. 
//
// VULNERABILITY DETAILS:
// CVE: N/A (Tool-based detection)
// CVSS: N/A
// Type: Backdoor / Remote Access Trojan (RAT) 
// Status: ACTIVE THREAT
// Patches: N/A - Targeted at post-exploitation persistence.
//
// EXPLOITATION REQUIREMENTS:
// - Initial infection via spear-phishing or watering hole attacks. 
// - Often utilizes DLL side-loading or masquerading as legitimate system files. 
// - Requires local execution privileges to establish command-and-control (C2) beacons. 
//
// USE CASES:
// - Identify infections by the Chrysalis/Lotus Blossom toolkit. 
// - Track lateral movement attempts involving custom APT backdoors. 
// - Support retrospective hunting against high-confidence APT indicators.
//
// MITRE ATT&CK MAPPING:
// Technique: T1059.003 - Command and Scripting Interpreter: Windows Command Shell 
// Technique: T1574.002 - Hijack Execution Flow: DLL Side-Loading 
// Tactics: Persistence, Execution, Command and Control 
//
// DATA SOURCE:
// Event Type: ProcessRollup2
// Required Fields: ImageFileName, CommandLine, ComputerName, UserName, SHA256HashData, @timestamp
// Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
// - Windows 10, 11 (All builds)
// - Windows Server 2016/2019/2022
//
// FALSE POSITIVES:
// - Legitimate binaries with hash collisions (highly improbable).
// - Security testing/Red Team simulations authorized by the organization.
//
// INVESTIGATION NOTES:
// 1. IMMEDIATE: Isolate any host matching these SHA256 hashes to prevent data exfiltration. 
// 2. Examine the 'CommandLine' to identify if the file was executed via a legitimate launcher.
// 3. Inspect 'DnsRequest' events for C2 domains associated with Lotus Blossom activity. 
// 4. Look for 'FileWrite' events in C:\Users\Public\ or %TEMP% directories created by this process.
//
// TUNING RECOMMENDATIONS:
// - If specific hashes match verified internal software (e.g., custom scripts), add to exclusion.
// - Filter out automated sandbox analysis systems if they trigger high volumes.
//
// REMEDIATION:
// Priority: CRITICAL
// Action: Quarantine the endpoint immediately. Collect memory forensics for C2 configuration.
//
// QUERY LOGIC:
// 1. Filters for the 'ProcessRollup2' event type (Process Executions).
// 2. Matches the 'SHA256HashData' against the Chrysalis Backdoor indicator list. 
// 3. Tables results for rapid triage of compromised assets.
//
// REFERENCES:
// - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/ 
//
//══════════════════════════════════════════════════════════════════════════════════════════════════

// Lead with the indexed event type for process executions
#event_simpleName = ProcessRollup2 

// Filter by the specific list of SHA256 hashes for the Chrysalis Backdoor 
| in(SHA256HashData, values=[
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

// Project the most relevant fields for investigation
| table([@timestamp, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine])

//══════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add frequency analysis (detect prevalence across fleet):
// | groupBy([SHA256HashData], function=[count(as=hit_count), collect(ComputerName, limit=5)])
// | sort(hit_count, order=desc)
//
// Correlate with network C2 activity:
// | join(query={ #event_simpleName=/NetworkConnect|DnsRequest/ }, field=TargetProcessId, include=[RemoteAddressIP4, DomainName])
//
// Hunt for specific persistence via registry:
// | join(query={ #event_simpleName=RegSetKey | filter(TargetKeyName=/CurrentVersion\\Run/) }, field=TargetProcessId, include=[TargetKeyName])
//
//══════════════════════════════════════════════════════════════════════════════════════════════════
