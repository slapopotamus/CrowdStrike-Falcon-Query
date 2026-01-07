//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// QUERY: PowerShell Steganography Detection (Tuoni C2 Framework)
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// Version: 1.0
// Author: Cybersecurity Operations
// Last Updated: 2025-11-20
//
// DESCRIPTION:
//   Detects PowerShell processes referencing image file extensions (.bmp, .png, .jpg) within the 
//   command line. This behavior is a high-fidelity indicator of the Tuoni C2 framework, which 
//   utilizes steganography to conceal malicious payloads within image pixels, bypassing 
//   traditional signature-based AV and script scanners.
//
// VULNERABILITY DETAILS:
//   Threat: Steganographic Payload Execution
//   Type: Defense Evasion / Command and Control (C2)
//   Status: ACTIVELY OBSERVED (Tuoni C2 Campaign - Nov 2025)
//   Risk Score: 8.2 (High)
//
// EXPLOITATION REQUIREMENTS:
//   - Execution of PowerShell with specific CLI arguments.
//   - Network access to retrieve remote image assets (optional, if hosted remotely).
//   - Local script execution permissions (though often bypassed via CLI flags).
//
// USE CASES:
//   - Detect potential Tuoni C2 steganography extraction.
//   - Identify obfuscated PowerShell scripts loading non-standard assets.
//   - Hunt for defense evasion techniques involving image-based payloads.
//
// MITRE ATT&CK MAPPING:
//   Technique: T1027.003 - Obfuscated Files or Information: Steganography
//   Sub-Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
//   Tactics: Defense Evasion, Execution
//
// DATA SOURCE:
//   Event Type: ProcessRollup2
//   Required Fields: CommandLine, FileName, ComputerName, @timestamp
//   Sensor: CrowdStrike Falcon EDR
//
// AFFECTED SYSTEMS:
//   - Windows 10/11 (All builds)
//   - Windows Server 2016/2019/2022/2025
//
// FALSE POSITIVES:
//   - Administrative scripts managing wallpaper/UI assets via PowerShell.
//   - Legitimate software installers using PowerShell to move image resources.
//   - Forensic tools or image processing automation.
//
// INVESTIGATION NOTES:
//   1. IMMEDIATE: Examine the full CommandLine for 'IEX', 'WebClient', or 'FromBase64String'.
//   2. Extract the URL or file path of the image referenced in the command line.
//   3. Check for outbound network connections (NetworkReceiveProcess) from the same PID.
//   4. Review process ancestry for the parent process of powershell.exe (e.g., cmd.exe, explorer.exe).
//   5. Retrieve the referenced image file for sandbox analysis to confirm payload presence.
//
// TUNING RECOMMENDATIONS:
//   - Filter out known-good administrative file paths (e.g., C:\Windows\Web\Wallpaper).
//   - Add thresholding for systems that perform frequent legitimate image processing.
//   - Join with NetworkConnectIP records to identify suspicious C2 infrastructure.
//
// REMEDIATION:
//   Priority: HIGH
//   Action: Isolate the host if the command line contains obfuscated/encoded strings.
//   Patches: N/A (Configuration-based; enforce PowerShell Constrained Language Mode).
//
// QUERY LOGIC:
//   1. Filter for ProcessRollup2 events where the filename is powershell.exe.
//   2. Apply regex to the CommandLine to identify image file extensions (.bmp, .png, .jpg).
//   3. Format the @timestamp to a human-readable "DetectionTime".
//   4. Project critical fields into a table and sort by most recent.
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName = "ProcessRollup2"
| FileName = "powershell.exe"
// Regex to find image extensions in the arguments (Case Insensitive)
| CommandLine = /.*\.(bmp|png|jpg).*/i
// Convert the raw epoch timestamp to a readable string
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, as="DetectionTime")
// Display the readable time and the specific command executed
| table([DetectionTime, ComputerName, UserName, CommandLine, ParentBaseFileName])
| sort(DetectionTime, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Add frequency analysis to identify unique/rare command lines:
// | groupBy([CommandLine], function=count(as=occurrence_count))
// | sort(occurrence_count, order=asc)
//
// Correlate with network connections to find C2 callback:
// | join(query={
//     #event_simpleName = /Network(Receive|Connect)Process/
//     | !RemoteAddressIP = /(127\.0\.0\.1|::1)/
//   }, field=TargetProcessId_decimal, include=[RemoteAddressIP, RemotePort])
//
// Identify hidden/encoded flags used alongside image loading:
// | CommandLine = /.*(-enc|-encodedcommand|-e|bypass).*/i
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
