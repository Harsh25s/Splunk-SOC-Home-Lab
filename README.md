# Splunk SOC Home Lab

End-to-end Security Operations Center home lab demonstrating practical detection engineering, SIEM administration, and MITRE ATT&CK-mapped threat detection across Windows endpoints.

## Architecture

![Architecture](architecture.png)

| Component | Role |
|-----------|------|
| Windows 11 VM (VirtualBox, Bridged) | Endpoint generating telemetry |
| Sysmon + SwiftOnSecurity config | Deep endpoint visibility |
| Splunk Universal Forwarder | Log shipping over TCP 9997 |
| Splunk Enterprise (Host) | SIEM, indexing, search, detection |

## Data Sources Ingested

| Sourcetype | Purpose |
|------------|---------|
| `WinEventLog:Security` | Authentication, account management |
| `WinEventLog:System` | System-level events |
| `WinEventLog:Application` | Application-level events |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Process, network, registry telemetry |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell scriptblock activity |

## Detections Engineered

| # | Detection | MITRE ID | Tactic | Data Source |
|---|-----------|----------|--------|-------------|
| 1 | Brute Force Logon | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access | Security 4625 |
| 2 | Suspicious PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution | Sysmon EID 1 |
| 3 | Account Creation / Priv Esc | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Persistence | Security 4720 / 4732 |
| 4 | C2-like Outbound Traffic | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Command & Control | Sysmon EID 3 |
| 5 | LOLBin Abuse | [T1218](https://attack.mitre.org/techniques/T1218/) | Defense Evasion | Sysmon EID 1 |

---

### Detection 1: Brute Force Logon (T1110)

**Use Case:** Detect repeated failed authentication attempts indicating credential brute forcing.

**SPL:**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, host
| where count > 5
| sort -count
```

**Validation:** Triggered via 8 simulated failed SMB authentication attempts.

![Detection 1 firing](screenshots/detection-1-bruteforce.png)

---

### Detection 2: Suspicious PowerShell (T1059.001)

**Use Case:** Identify obfuscated or encoded PowerShell execution commonly used in fileless attacks.

**SPL:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*DownloadString*" OR CommandLine="*-nop*" OR CommandLine="*bypass*" OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*")
| table _time, host, User, CommandLine, ParentImage
```

**Validation:** Triggered via base64-encoded PowerShell and execution policy bypass commands.

![Detection 2 firing](screenshots/detection-2-powershell.png)

---

### Detection 3: Account Creation / Privilege Escalation (T1136.001)

**Use Case:** Detect creation of new local accounts and addition to privileged groups — a common persistence technique.

**SPL:**
```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, host, TargetUserName, SubjectUserName, EventCode
```

**Validation:** Triggered by creating a local user and adding it to the Administrators group.

![Detection 3 firing](screenshots/detection-3-account-creation.png)

---

### Detection 4: Suspicious Outbound C2-like Traffic (T1071.001)

**Use Case:** Detect processes generating high volumes of outbound connections to public IPs — possible beaconing or C2 activity.

**SPL:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
NOT DestinationIp IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.1")
| stats count by Image, DestinationIp, DestinationPort, host
| where count > 3
| sort -count
```

**Validation:** Triggered by repeated outbound HTTPS requests via PowerShell Invoke-WebRequest.

![Detection 4 firing](screenshots/detection-4-outbound-traffic.png)

---

### Detection 5: LOLBin Abuse (T1218)

**Use Case:** Detect execution of "Living Off the Land" binaries (certutil, rundll32, bitsadmin, etc.) commonly abused by attackers for defense evasion.

**SPL:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| table _time, host, Image, ParentImage, CommandLine, User
```

**Validation:** Triggered via certutil download, rundll32 invocation, and bitsadmin commands.

![Detection 5 firing](screenshots/detection-5-lolbin.png)

---

## Setup Notes & Troubleshooting

Some real-world issues encountered and resolved:

- **Splunk license expiration:** Trial expired on install — switched to Splunk Free license (500 MB/day, no time limit) by editing license group under Settings.
- **Forgotten admin password:** Reset via `user-seed.conf` after stopping the splunkd service.
- **Forwarder CLI `add monitor` failures:** Newer Universal Forwarder versions reject the `add monitor` / `add eventlog` syntax for Windows Event Logs. Resolved by writing `inputs.conf` directly under `etc/system/local/`.
- **Sysmon channel access denied (errorCode=5):** Universal Forwarder service was running under an account lacking permission to subscribe to the Sysmon event log channel. Resolved by reconfiguring the SplunkForwarder service to run as **Local System**.

## Lessons Learned

- Sysmon command-line telemetry is the highest-signal endpoint data source for detection engineering
- Default Windows Security logs alone miss most attacker TTPs (LOLBins, fileless execution, parent-child anomalies)
- Threshold-based detections (`count > N`) require baselining normal activity before deployment
- MITRE ATT&CK mapping forces structured thinking about coverage gaps, not just individual rules
- Permissions issues (errorCode=5) are common with custom event log channels — service account context matters

## Future Enhancements

- Add Linux endpoint with auditd / journald via Universal Forwarder
- Convert Sigma rules to SPL for broader coverage
- Build correlation searches linking multiple detections (e.g., suspicious PowerShell → outbound connection)
- Integrate Atomic Red Team for systematic attack simulation
- Deploy Splunk SOAR / Phantom for response automation

---

**Author:** Harsh Sharma 

