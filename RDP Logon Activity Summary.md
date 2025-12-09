// Title: RDP Logon Activity Summary
// Version: 1.0
// Last Modified: 2025-12-08
// Description: Identifies Remote Desktop Protocol (RDP) logon sessions by detecting
//              LogonType 10 events and aggregating by host, user, and source IP.
//              Excludes localhost connections to focus on remote access activity.
// Use Cases:
//   - Monitor for unauthorized remote access to endpoints
//   - Identify lateral movement via RDP
//   - Audit remote administration activity
//   - Investigate suspicious remote sessions from unusual IPs
// MITRE ATT&CK:
//   - T1021.001 Remote Services: Remote Desktop Protocol
//   - T1078 Valid Accounts (if attacker uses compromised credentials)
//   - T1563.002 Remote Service Session Hijacking: RDP Hijacking
// Output Description:
//   - ComputerName: Target host receiving the RDP connection
//   - UserName: Account used for the RDP session
//   - RemoteAddressIP4: Source IP initiating the connection
//   - UserSid_readable: Security identifier of the user
//   - session_count: Total number of RDP sessions for this combination
//   - first_seen_readable: Earliest session timestamp (US Eastern)
//   - last_seen_readable: Most recent session timestamp (US Eastern)

#event_simpleName = UserLogon
| LogonType = 10
| RemoteAddressIP4 != "127.0.0.1"
| groupBy([ComputerName, UserName, RemoteAddressIP4, UserSid_readable], function=[count(), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| rename(field=_count, as=session_count)
| first_seen_readable := formatTime("%Y-%m-%d %H:%M:%S", field=first_seen, timezone="America/New_York")
| last_seen_readable := formatTime("%Y-%m-%d %H:%M:%S", field=last_seen, timezone="America/New_York")
| drop([first_seen, last_seen])
| sort(session_count, order=desc)
