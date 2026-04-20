//══════════════════════════════════════════════════════════════════════════════════════════════════
// Post-Access Enumeration Commands - Suspicious Staging Activity (Expanded)
//══════════════════════════════════════════════════════════════════════════════════════════════════
// Version: 2.0
// Author: Cybersecurity Operations
// Last Updated: 2026-04-20
//
// DESCRIPTION:
// Identifies common hands-on-keyboard Windows enumeration commands often seen during
// early post-access staging. Covers account/group discovery, credential staging,
// system/network reconnaissance, session enumeration, and domain trust discovery.
//
// THREAT CONTEXT:
// Risk Level: Medium (individual events) / High (clustered activity - see correlation variant)
// Status: HUNT / CONTEXTUAL DETECTION
// Note: Many of these commands are common in legitimate administration. Best used for
// correlation and scoping. See the correlation query below to surface clustered activity.
//
// MITRE ATT&CK MAPPING:
// - T1033: System Owner/User Discovery      (whoami)
// - T1069.001/002: Permission Groups Discovery (net localgroup / net group)
// - T1087.001/002: Account Discovery         (net user / net accounts)
// - T1082: System Information Discovery      (systeminfo, hostname, ver)
// - T1016: System Network Configuration      (ipconfig, route, arp)
// - T1049: System Network Connections        (netstat, net session, net use)
// - T1135: Network Share Discovery           (net view, net share)
// - T1057: Process Discovery                 (tasklist, qprocess)
// - T1007: System Service Discovery          (tasklist /svc, sc query)
// - T1482: Domain Trust Discovery            (nltest /domain_trusts)
// - T1555: Credentials from Password Stores  (cmdkey /list)
// - T1033: User Session Discovery            (quser, qwinsta, query user)
//
// DATA SOURCE:
// Event Type: ProcessRollup2
// Required Fields: FileName, CommandLine, ParentBaseFileName, UserName, ComputerName, aid
// Sensor: CrowdStrike Falcon EDR
//
// FALSE POSITIVES:
// - Helpdesk or sysadmin troubleshooting
// - Inventory / configuration management scripts (SCCM, Tanium, Ansible)
// - Login scripts running net use / net session
// - Security tools and internal red team activity
//
// INVESTIGATION NOTES:
// 1. Review the parent process - cmd.exe / powershell.exe with interactive ancestry is
//    higher signal than service/scheduled-task parents.
// 2. Use the correlation variant below to find hosts where multiple distinct
//    enumeration commands occurred in a short window (strong HoK indicator).
// 3. Pivot on aid + UserName to see full operator activity timeline.
// 4. Correlate with credential access (mimikatz, lsass dumps), Defender tampering,
//    or subsequent lateral movement (PsExec, WMI, WinRM).
//══════════════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName = ProcessRollup2
| event_platform = Win
| in(FileName, values=[
    "whoami.exe","cmdkey.exe","net.exe","net1.exe","nltest.exe",
    "systeminfo.exe","hostname.exe","ipconfig.exe","route.exe","arp.exe",
    "netstat.exe","tasklist.exe","qprocess.exe","sc.exe",
    "quser.exe","qwinsta.exe","query.exe","reg.exe","wmic.exe"
  ], ignoreCase=true)
| case {
    // ── Account / Privilege / Group Discovery ──────────────────────────────
    FileName = /^whoami\.exe$/i     and CommandLine = */priv*      | stage := "acct-whoami-priv";      tactic := "Discovery"; technique := "T1033";
    FileName = /^whoami\.exe$/i     and CommandLine = */groups*    | stage := "acct-whoami-groups";    tactic := "Discovery"; technique := "T1069";
    FileName = /^whoami\.exe$/i     and CommandLine = */all*       | stage := "acct-whoami-all";       tactic := "Discovery"; technique := "T1033";
    FileName = /^net1?\.exe$/i      and CommandLine = /\bgroup\b/i      | stage := "acct-net-group";        tactic := "Discovery"; technique := "T1069.002";
    FileName = /^net1?\.exe$/i      and CommandLine = /\blocalgroup\b/i | stage := "acct-net-localgroup";   tactic := "Discovery"; technique := "T1069.001";
    FileName = /^net1?\.exe$/i      and CommandLine = /\buser\b/i       | stage := "acct-net-user";         tactic := "Discovery"; technique := "T1087";
    FileName = /^net1?\.exe$/i      and CommandLine = /\baccounts\b/i   | stage := "acct-net-accounts";     tactic := "Discovery"; technique := "T1201";

    // ── Credential Staging ─────────────────────────────────────────────────
    FileName = /^cmdkey\.exe$/i     and CommandLine = */list*      | stage := "cred-cmdkey-list";      tactic := "CredentialAccess"; technique := "T1555";

    // ── Domain Trust / AD Discovery ────────────────────────────────────────
    FileName = /^nltest\.exe$/i     and CommandLine = */domain_trusts* | stage := "dom-nltest-trusts"; tactic := "Discovery"; technique := "T1482";
    FileName = /^nltest\.exe$/i     and CommandLine = */dclist*    | stage := "dom-nltest-dclist";     tactic := "Discovery"; technique := "T1018";

    // ── System Info Discovery ──────────────────────────────────────────────
    FileName = /^systeminfo\.exe$/i                                | stage := "sys-systeminfo";        tactic := "Discovery"; technique := "T1082";
    FileName = /^hostname\.exe$/i                                  | stage := "sys-hostname";          tactic := "Discovery"; technique := "T1082";

    // ── Network Config Discovery ───────────────────────────────────────────
    FileName = /^ipconfig\.exe$/i   and CommandLine = */all*       | stage := "net-ipconfig-all";      tactic := "Discovery"; technique := "T1016";
    FileName = /^route\.exe$/i      and CommandLine = /\bprint\b/i | stage := "net-route-print";       tactic := "Discovery"; technique := "T1016";
    FileName = /^arp\.exe$/i        and CommandLine = */a*         | stage := "net-arp-cache";         tactic := "Discovery"; technique := "T1016";

    // ── Network Connections / Sessions / Shares ────────────────────────────
    FileName = /^netstat\.exe$/i                                   | stage := "net-netstat";           tactic := "Discovery"; technique := "T1049";
    FileName = /^net1?\.exe$/i      and CommandLine = /\bsession\b/i    | stage := "net-net-session";       tactic := "Discovery"; technique := "T1049";
    FileName = /^net1?\.exe$/i      and CommandLine = /\buse\b/i        | stage := "net-net-use";           tactic := "Discovery"; technique := "T1049";
    FileName = /^net1?\.exe$/i      and CommandLine = /\bview\b/i       | stage := "net-net-view";          tactic := "Discovery"; technique := "T1135";
    FileName = /^net1?\.exe$/i      and CommandLine = /\bshare\b/i      | stage := "net-net-share";         tactic := "Discovery"; technique := "T1135";

    // ── Process / Service Discovery ────────────────────────────────────────
    FileName = /^tasklist\.exe$/i   and CommandLine = */svc*       | stage := "proc-tasklist-svc";     tactic := "Discovery"; technique := "T1007";
    FileName = /^tasklist\.exe$/i                                  | stage := "proc-tasklist";         tactic := "Discovery"; technique := "T1057";
    FileName = /^qprocess\.exe$/i                                  | stage := "proc-qprocess";         tactic := "Discovery"; technique := "T1057";
    FileName = /^sc\.exe$/i         and CommandLine = /\bquery\b/i | stage := "svc-sc-query";          tactic := "Discovery"; technique := "T1007";

    // ── Session Discovery ──────────────────────────────────────────────────
    FileName = /^quser\.exe$/i                                     | stage := "sess-quser";            tactic := "Discovery"; technique := "T1033";
    FileName = /^qwinsta\.exe$/i                                   | stage := "sess-qwinsta";          tactic := "Discovery"; technique := "T1033";
    FileName = /^query\.exe$/i      and CommandLine = /\buser\b/i  | stage := "sess-query-user";       tactic := "Discovery"; technique := "T1033";

    // ── Registry / WMI Recon ───────────────────────────────────────────────
    FileName = /^reg\.exe$/i        and CommandLine = /\bquery\b/i and CommandLine = /winlogon|currentversion\\run|lsa/i
        | stage := "reg-recon-autoruns-lsa"; tactic := "Discovery"; technique := "T1012";
    FileName = /^wmic\.exe$/i       and CommandLine = /\b(useraccount|group|computersystem|process|service|qfe)\b/i
        | stage := "wmic-recon"; tactic := "Discovery"; technique := "T1047";
  }
| stage = *
| table([@timestamp, stage, tactic, technique, aid, ComputerName, UserName,
         ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=500)
| sort(@timestamp, order=desc)
