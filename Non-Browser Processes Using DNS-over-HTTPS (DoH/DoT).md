//═══════════════════════════════════════════════════════════════════════════════
// QUERY: Hunt - Non-Browser Processes Using DNS-over-HTTPS (DoH/DoT)
//═══════════════════════════════════════════════════════════════════════════════
// Version: 1.4
// Author: Security Operations
// Last Updated: 2025-12-17
//
// DESCRIPTION:
//   Identifies non-browser processes initiating connections to known encrypted 
//   DNS providers (DoH/DoT). Attackers use these protocols to bypass legacy 
//   DNS monitoring, tunnel C2 traffic, and exfiltrate data.
//
// MITRE ATT&CK MAPPING:
//   Technique: T1071.001 (Application Layer Protocol: Web Protocols)
//   Technique: T1572 (Protocol Tunneling)
//
// USE CASES:
//   - Detect potential C2 communication via encrypted channels.
//   - Identify unauthorized use of privacy tools or VPNs.
//   - Audit internal applications bypassing corporate DNS policy.
//
// DATA SOURCE:
//   Event Type: NetworkConnectIP4
//   Required Fields: RemoteAddressIP4, RemotePort, ContextBaseFileName
//
// FALSE POSITIVES:
//   - Legitimate VPN clients (Cisco AnyConnect, GlobalProtect).
//   - Privacy-focused software (Signal, Tor).
//   - Corporate security agents utilizing encrypted resolution.
//
// PERFORMANCE NOTES:
//   - Uses #event_simpleName tag filter for initial fast indexing.
//   - Implements field-specific regex for process exclusions.
//   - Ordered filters to drop high-volume traffic early.
//
//═══════════════════════════════════════════════════════════════════════════════

// Step 1: Filter by indexed tag and specific DoH/DoT ports
#event_simpleName = NetworkConnectIP4 
| Protocol = "6"
| in(RemotePort, values=["443", "5053", "853", "8443", "4443"])

// Step 2: Match against known encrypted DNS provider IPs
| in(RemoteAddressIP4, values=[
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", // Cloudflare
    "8.8.8.8", "8.8.4.4", // Google
    "9.9.9.9", "9.9.9.10", "9.9.9.11", "149.112.112.112", // Quad9
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123", // OpenDNS
    "45.90.28.0", "45.90.30.0", // NextDNS
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", // AdGuard
    "185.228.168.168", "185.228.169.168", "185.228.168.10", "185.228.169.11", // CleanBrowsing
    "194.242.2.2", "194.242.2.3", // Mullvad
    "76.76.2.0", "76.76.10.0" // Control D
])

// Step 3: Exclude known browsers and system resolvers using optimized regex
| !(ContextBaseFileName = /^(chrome|msedge|firefox|brave|opera|iexplore|safari|vivaldi|waterfox|librewolf)\.exe$/i)
| !(ContextBaseFileName = /^(svchost|dns|systemd-resolved|dnsmasq)\.exe$/i)

// Step 4: Present findings for investigation
| table([@timestamp, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort, LocalAddressIP4])
| sort(@timestamp, order=desc)
