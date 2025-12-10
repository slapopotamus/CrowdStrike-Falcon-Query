// ============================================================================
// Hunt: Non-Browser Processes Using DNS-over-HTTPS (DoH/DoT)
// ============================================================================
// MITRE ATT&CK: T1071.001 (Web Protocols), T1572 (Protocol Tunneling)
// Version: 1.3
// Last Updated: 2025-12-10
//
// Use Case: Detect potential C2/exfiltration via encrypted DNS channels
//           by identifying non-browser processes connecting to known
//           DoH/DoT provider IPs on encrypted DNS ports
//
// Ports Monitored:
//   443  - Standard HTTPS (DoH)
//   853  - DNS-over-TLS (DoT)
//   5053 - Quad9 alternate DoH
//   8443 - Alternate HTTPS DoH
//   4443 - Alternate HTTPS DoH
//
// Providers Monitored:
//   Cloudflare, Google, Quad9, OpenDNS/Cisco Umbrella, NextDNS,
//   AdGuard, CleanBrowsing, Mullvad, Control D
//
// False Positive Guidance:
//   - VPN clients may use DoH for DNS resolution
//   - Privacy-focused applications (Tor, Signal)
//   - Corporate DNS security tools
//   - Review ContextBaseFileName for legitimacy before escalation
// ============================================================================

#event_simpleName = NetworkConnectIP4
| Protocol = "6"
| in(RemotePort, values=["443", "5053", "853", "8443", "4443"])
| in(RemoteAddressIP4, values=[
    // Cloudflare
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",         // Malware blocking
    "1.0.0.2",
    "1.1.1.3",         // Adult content blocking
    "1.0.0.3",
    // Google
    "8.8.8.8",
    "8.8.4.4",
    // Quad9
    "9.9.9.9",
    "9.9.9.10",        // No threat blocking
    "9.9.9.11",        // With ECS
    "149.112.112.112",
    "149.112.112.10",
    "149.112.112.11",
    // OpenDNS / Cisco Umbrella
    "208.67.222.222",
    "208.67.220.220",
    "208.67.222.123",
    "208.67.220.123",
    // NextDNS
    "45.90.28.0",
    "45.90.30.0",
    // AdGuard
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.15",    // Family protection
    "94.140.15.16",
    // CleanBrowsing
    "185.228.168.168",
    "185.228.169.168",
    "185.228.168.10",  // Adult filter
    "185.228.169.11",
    // Mullvad
    "194.242.2.2",
    "194.242.2.3",
    // Control D
    "76.76.2.0",
    "76.76.10.0"
])

// Exclude browsers
| ContextBaseFileName != /^(chrome|msedge|firefox|brave|opera|iexplore|safari|vivaldi|waterfox|librewolf)\.exe$/i

// Exclude legitimate system DNS resolvers
| ContextBaseFileName != /^(svchost|dns|systemd-resolved|dnsmasq)\.exe$/i

| table([@timestamp, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort, LocalAddressIP4])
| sort(@timestamp, order=desc)
