//══════════════════════════════════════════════════════════════════════════════════════════════════
// Post-Access Enumeration - High-Signal Indicators Only
//══════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 3.0-skinny
// Last Updated: 2026-04-20
//
// SCOPE:
// Only the highest-signal post-access enumeration commands — the ones that are
// strong HoK indicators even as single events. Noisy admin/inventory commands
// (systeminfo, hostname, netstat, tasklist without /svc, sc query, etc.) have
// been removed. Use v2.2 if you need full coverage for correlation work.
//
// WHY THESE SPECIFIC COMMANDS:
// - whoami /priv /groups /all  → operator verifying what they landed as
// - cmdkey /list               → stored credential harvest (almost never benign)
// - nltest /domain_trusts      → AD trust enumeration (lateral movement prep)
// - net localgroup administrators / net group "Domain Admins" → specific high-value targets
// - reg query ... LSA / autoruns → credential access or persistence recon
//
// MITRE ATT&CK:
// T1033, T1069, T1087, T1482, T1555, T1012
//══════════════════════════════════════════════════════════════════════════════════════════════════

event_platform=Win
| #event_simpleName=ProcessRollup2
| in(FileName, values=[
    "whoami.exe","cmdkey.exe","net.exe","net1.exe","nltest.exe","reg.exe"
  ], ignoreCase=true)

// Drop known RMM/monitoring/inventory agents (expand list as needed)
| ParentBaseFileName != /^(NinjaRMMAgent|NinjaRMM|TaniumClient|CcmExec|MsSense|MonitoringHost|kaseya|connectwise|screenconnect|n-able|datto|automate|LTSvc)\.exe$/i

| case {
    // Identity & privilege checks
    FileName=/^whoami\.exe$/i and CommandLine=/\s\/priv\b/i       | stage:="whoami-priv"      | technique:="T1033";
    FileName=/^whoami\.exe$/i and CommandLine=/\s\/groups\b/i     | stage:="whoami-groups"    | technique:="T1069";
    FileName=/^whoami\.exe$/i and CommandLine=/\s\/all\b/i        | stage:="whoami-all"       | technique:="T1033";

    // Stored credential harvest
    FileName=/^cmdkey\.exe$/i and CommandLine=/\s\/list\b/i       | stage:="cmdkey-list"      | technique:="T1555";

    // Domain trust / DC discovery
    FileName=/^nltest\.exe$/i and CommandLine=/\/domain_trusts\b/i| stage:="nltest-trusts"    | technique:="T1482";
    FileName=/^nltest\.exe$/i and CommandLine=/\/dclist\b/i       | stage:="nltest-dclist"    | technique:="T1018";

    // High-value group enumeration (only flag specific privileged targets)
    FileName=/^net1?\.exe$/i  and CommandLine=/\blocalgroup\b/i and CommandLine=/\b(administrators|remote\s+desktop\s+users)\b/i
        | stage:="net-localgroup-priv" | technique:="T1069.001";
    FileName=/^net1?\.exe$/i  and CommandLine=/\bgroup\b/i and CommandLine=/("domain\s+admins"|"enterprise\s+admins"|"schema\s+admins")/i
        | stage:="net-group-priv" | technique:="T1069.002";

    // Credential/persistence registry recon
    FileName=/^reg\.exe$/i    and CommandLine=/\bquery\b/i and CommandLine=/\\lsa\b/i
        | stage:="reg-lsa"     | technique:="T1012";
    FileName=/^reg\.exe$/i    and CommandLine=/\bquery\b/i and CommandLine=/currentversion\\run/i
        | stage:="reg-autoruns"| technique:="T1012";
  }
| stage = *
| table([@timestamp, stage, technique, aid, ComputerName, UserName,
         ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=desc)
