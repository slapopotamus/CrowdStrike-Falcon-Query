// Windows IFEO Debugger and SilentProcessExit Hijacking
//
// Detects registry changes that can abuse Image File Execution Options (IFEO)
// or SilentProcessExit to launch attacker-controlled commands.
//
// MITRE:
// - T1546.012 - Image File Execution Options Injection
// - T1112 - Modify Registry

event_platform=Win #event_simpleName=RegGenericValue

// Scope to IFEO and SilentProcessExit registry paths.
// Includes native and WOW6432Node registry views.
| RegObjectName=/\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\(Image File Execution Options|SilentProcessExit)\\/i

// These values either launch the payload or enable SilentProcessExit behavior.
| RegValueName=/^(Debugger|MonitorProcess|GlobalFlag|ReportingMode)$/i

// Normalize possible registry value fields. Adjust field names if your tenant
// stores DWORD/string data under different registry value fields.
| coalesce([RegStringValue, RegNumericValue, RegValueData, RegValue, RegDWORDValue, "-"], as=RegistryValue)

// Identify registry view for analyst context.
| case {
    RegObjectName=/\\WOW6432Node\\/i | RegistryView := "WOW6432Node";
    *                              | RegistryView := "Native";
  }

// Extract target executable and persistence mechanism.
| case {
    RegObjectName=/\\Image File Execution Options\\(?<TargetImage>[^\\]+)(?:\\|$)/i
      | PersistenceMechanism := "IFEO Debugger";
    RegObjectName=/\\SilentProcessExit\\(?<TargetImage>[^\\]+)(?:\\|$)/i
      | PersistenceMechanism := "SilentProcessExit Monitor";
    *
      | PersistenceMechanism := "Unknown IFEO/SilentProcessExit";
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
    *
      | TargetCategory := "Other target";
  }

// Classify the payload or setup value.
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
      | ValueIndicator := "Executable or script payload";
    RegValueName=/^(GlobalFlag|ReportingMode)$/i
      | ValueIndicator := "SilentProcessExit setup value";
    *
      | ValueIndicator := "Review value";
  }

// Label common benign debugger tooling instead of excluding it.
// This preserves visibility while still helping triage.
| case {
    RegistryValue=/\\Windows Kits\\|\\Microsoft Visual Studio\\|\\Debugging Tools for Windows\\|\\vsjitdebugger\.exe/i
      | ToolingContext := "Likely developer/debugger tooling";
    *
      | ToolingContext := "No common benign tooling match";
  }

// Assign hunt severity.
| case {
    RegValueName=/^(Debugger|MonitorProcess)$/i
      AND ValueIndicator=/obfuscation|URL|UNC path|LOLBIN|User-writable|payload/i
      | Severity := "High" | SeverityScore := 90;

    TargetCategory=/Accessibility binary|Core Windows process/i
      AND RegValueName=/^(Debugger|MonitorProcess)$/i
      | Severity := "High" | SeverityScore := 85;

    PersistenceMechanism="SilentProcessExit Monitor"
      AND RegValueName=/^(GlobalFlag|ReportingMode)$/i
      | Severity := "Medium" | SeverityScore := 60;

    RegValueName=/^(Debugger|MonitorProcess)$/i
      | Severity := "Medium" | SeverityScore := 50;

    *
      | Severity := "Low" | SeverityScore := 20;
  }

// Final analyst view.
| table([
    @timestamp,
    Severity,
    SeverityScore,
    PersistenceMechanism,
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
