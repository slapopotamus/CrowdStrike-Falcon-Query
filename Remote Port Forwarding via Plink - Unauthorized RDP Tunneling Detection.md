//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// Remote Port Forwarding via Plink - Unauthorized RDP Tunneling Detection
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// VERSION: 1.2
// AUTHOR: Cybersecurity Operations
// LAST UPDATED: 2026-02-26
//
// DESCRIPTION:
//   Detects the use of Plink (PuTTY Link) to establish encrypted SSH tunnels specifically
//   targeting RDP traffic (port 3389). This allows attackers to bypass firewall boundaries
//   and tunnel RDP sessions through port 22 or 443.
//
// VULNERABILITY DETAILS:
//   Technique: Remote Reverse SSH Tunneling (T1572)
//   Type: Defense Evasion / Lateral Movement
//   Mechanism: Attackers use -R or -L flags to map local RDP ports to remote SSH listeners, 
//              effectively "punching a hole" through the perimeter.
//
// MITRE ATT&CK MAPPING:
//   - T1572: Protocol Tunneling
//   - T1021.004: Remote Services: SSH Hijacking
//
// VALIDATION & TESTING:
//   Execute the following PowerShell commands to verify detection triggers:
//   1. Download: Invoke-WebRequest -Uri "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" -OutFile "$env:TEMP\plink.exe"
//   2. Test -R:  & "$env:TEMP\plink.exe" -R 4444:localhost:3389 user@192.168.1.1
//   3. Test -L:  & "$env:TEMP\plink.exe" -L 4444:localhost:3389 user@192.168.1.1
//
// INVESTIGATION NOTES:
//   - Identify the destination IP in the CommandLine (-R or -L flags).
//   - Check for subsequent RDP login events (UserLogon) following the tunnel establishment.
//   - Pivot to NetworkConnectIP4 to identify the external C2/SSH server.
//
// TUNING RECOMMENDATIONS:
//   - Filter out authorized Jump Hosts or DevOps workstations via 'ComputerName'.
//   - Monitor for renamed plink.exe by searching for OriginalFilename="plink.exe".
//
// REMEDIATION:
//   - Kill the identified PID immediately.
//   - Block the remote SSH destination IP at the perimeter firewall.
//
// QUERY LOGIC:
//   1. Filters for ProcessRollup2 (Process Executions).
//   2. Targets the Plink binary (supports 32/64 bit naming).
//   3. Regex matches for tunneling flags (-R or -L) followed by the RDP port (3389).
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════

#event_simpleName=ProcessRollup2
| ImageFileName=/\\plink(64)?\.exe$/i
| CommandLine=/\s-(R|L).*:3389/i
| table([aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, @timestamp])
| sort(@timestamp, order=desc)

//══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ENHANCEMENT OPTIONS:
//
// Join with Network data to find the C2 Server IP:
// | join(query={#event_simpleName=NetworkConnectIP4}, field=aid, include=[RemoteIP])
//
// Identify if the tunnel was successful by checking for localhost RDP connections:
// | join(query={#event_simpleName=UserLogon | RemoteIP="127.0.0.1"}, field=aid)
//
//══════════════════════════════════════════════════════════════════════════════════════════════════════════
