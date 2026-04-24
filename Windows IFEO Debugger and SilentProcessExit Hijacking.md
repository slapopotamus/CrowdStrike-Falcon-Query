// Windows IFEO, SilentProcessExit, and VerifierDlls Hijacking
//
// Purpose:
// Detect registry changes that may abuse Windows Image File Execution Options
// (IFEO), SilentProcessExit, or AppVerifier-related VerifierDlls values for
// persistence, privilege escalation, or defense evasion.
//
// Why it matters:
// IFEO is a legitimate Windows debugging feature. Attackers can set a Debugger
// value so launching a target executable also launches attacker-controlled code.
//
// SilentProcessExit can launch a MonitorProcess when a target process exits,
// usually after related IFEO setup values are configured.
//
// VerifierDlls can be abused through Application Verifier-style IFEO settings to
// load attacker-controlled DLLs into targeted processes.
//
// MITRE ATT&CK:
// - T1546.012 - Event Triggered Execution: Image File Execution Options Injection
// - T1112 - Modify Registry

event_platform=Win #event_simpleName=RegGenericValue

// Scope to IFEO and SilentProcessExit registry paths.
// Includes native and WOW6432Node registry views.
| RegObjectName=/\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\(Image File Execution Options|SilentProcessExit)\\/i

// Values of interest:
// - Debugger: classic IFEO hijack payload value
// - MonitorProcess: SilentProcessExit payload value
// - GlobalFlag / ReportingMode: common setup values for SilentProcessExit behavior
// - VerifierDlls: AppVerifier-style DLL load abuse
| RegValueName=/^(Debugger|MonitorProcess|GlobalFlag|ReportingMode|VerifierDlls)$/i

// Normalize possible registry value fields.
// Adjust field names if your tenant stores registry data differently.
| coalesce([RegStringValue, RegNumericValue, RegValueData, RegValue, RegDWORDValue, "-"], as=RegistryValue)

// Identify registry view for analyst context.
| case {
    RegObjectName=/\\WOW6432Node\\/i | RegistryView := "WOW6432Node";
    *                              | RegistryView := "Native";
  }

// Extract target executable and persistence mechanism.
// TargetImage is the executable being hijacked or monitored.
| case {
    RegObjectName=/\\Image File Execution Options\\(?<TargetImage>[^\\]+)(?:\\|$)/i
      | PersistenceMechanism := "IFEO / AppVerifier";
    RegObjectName=/\\SilentProcessExit\\(?<TargetImage>[^\\]+)(?:\\|$)/i
      | PersistenceMechanism := "SilentProcessExit Monitor";
    *
      | PersistenceMechanism := "Unknown IFEO/SilentProcessExit";
  }

// Make the exact abuse pattern easier to understand.
| case {
    RegValueName="Debugger"
      | AbusePattern := "IFEO Debugger hijack";
    RegValueName="MonitorProcess"
      | AbusePattern := "SilentProcessExit monitor process";
    RegValueName="VerifierDlls"
      | AbusePattern := "AppVerifier DLL injection";
    RegValueName=/^(GlobalFlag|ReportingMode)$/i
      | AbusePattern := "SilentProcessExit or VerifierDlls setup value";
    *
      | AbusePattern := "Review IFEO-related value";
  }

// Classify the executable being hijacked.
| case {
    TargetImage=/^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$/i
      | TargetCategory := "Accessibility binary";
    TargetImage=/^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|wmic|mmc)\.exe$/i
      | TargetCategory := "LOLBIN or script host";
    TargetImage=/^(taskmgr|procexp|procmon|autoruns|regedit|services|eventvwr)\.exe$/i
      | TargetCategory := "Admin or inspection tool";
    TargetImage=/^(lsass|winlogon|csrss|smss|services|svchost|explorer)\.exe$/i
      | TargetCategory := "Core Windows process";
    TargetImage=/^(msmpeng|windefend|sense|securityhealthservice|csfalconservice|csagent|carbonblack|cbdefense|sentinelagent|sentinelone|tanium|qualys|nessus|splunkd|elastic-agent)\.exe$/i
      | TargetCategory := "Security or management tool";
    *
      | TargetCategory := "Other target";
  }

// Classify the registry value data.
// Order matters: higher-signal indicators are evaluated first.
| case {
    RegistryValue=/\-(enc|encodedcommand|e)\b|frombase64string|iex|invoke-expression|downloadstring|webclient/i
      | ValueIndicator := "PowerShell or script obfuscation";
    RegistryValue=/https?:\/\//i
      | ValueIndicator := "URL in registry value";
    RegistryValue=/^\\\\[^\\]+\\/i
      | ValueIndicator := "UNC path";
    RegistryValue=/\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|wmic|installutil|msbuild|regasm|regsvcs)\.exe\b/i
      | ValueIndicator := "LOLBIN or script host in value";
    RegistryValue=/\\Users\\|\\ProgramData\\|\\AppData\\|\\Windows\\Temp\\|\\Temp\\/i
      | ValueIndicator := "User-writable path";
    RegistryValue=/\.(bat|cmd|ps1|vbs|js|jse|hta|sct|dll|exe)(\s|$|")/i
      | ValueIndicator := "Executable, DLL, or script payload";
    RegValueName=/^(GlobalFlag|ReportingMode)$/i
      | ValueIndicator := "Setup value";
    *
      | ValueIndicator := "Review value";
  }

// Label common benign debugger tooling instead of excluding it.
// Tune this for your environment before promoting to alerting.
| case {
    RegistryValue=/\\Windows Kits\\|\\Microsoft Visual Studio\\|\\Debugging Tools for Windows\\|\\vsjitdebugger\.exe/i
      | ToolingContext := "Likely developer/debugger tooling";
    *
      | ToolingContext := "No common benign tooling match";
  }

// Assign hunt severity.
// This is a triage label, not a final verdict.
| case {
    RegValueName=/^(Debugger|MonitorProcess|VerifierDlls)$/i
      AND ValueIndicator=/obfuscation|URL|UNC path|LOLBIN|User-writable|payload/i
      | Severity := "High" | SeverityScore := 95;

    TargetCategory=/Accessibility binary|Core Windows process|Security or management tool/i
      AND RegValueName=/^(Debugger|MonitorProcess|VerifierDlls)$/i
      | Severity := "High" | SeverityScore := 90;

    PersistenceMechanism="SilentProcessExit Monitor"
      AND RegValueName=/^(GlobalFlag|ReportingMode)$/i
      | Severity := "Medium" | SeverityScore := 60;

    RegValueName=/^(Debugger|MonitorProcess|VerifierDlls)$/i
      | Severity := "Medium" | SeverityScore := 55;

    *
      | Severity := "Low" | SeverityScore := 20;
  }

// Final analyst view.
| table([
    @timestamp,
    Severity,
    SeverityScore,
    PersistenceMechanism,
    AbusePattern,
    RegistryView,
    TargetImage,
    TargetCategory,
    ValueIndicator,
    ToolingContext,
    aid,
    ComputerName,
    UserName,
    RegObjectName,
    RegValueName,
    RegistryValue,
    ProcessImageFileName,
    AuthenticationID
  ], sortby=SeverityScore, order=desc, limit=2000)
