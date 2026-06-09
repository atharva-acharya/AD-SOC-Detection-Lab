# IR-005 — PsExec Lateral Movement Detection

**Date:** 09 June 2026  
**Analyst:** Atharva  
**Severity:** Critical  
**Status:** Resolved (Lab Simulation)  
**MITRE ATT&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares

---

## 1. Alert Summary

Five instances of a new service being installed on WIN10-Victim were detected
within a 27-minute window. Each service used a randomly generated short name
and a randomly named executable dropped into %systemroot%. This pattern is
the definitive signature of Impacket PsExec lateral movement — the attacker
used Administrator credentials obtained from the DCSync attack (IR-003) to
move laterally from their Kali machine into WIN10-Victim.

| Field | Value |
|-------|-------|
| Source Host | 10.0.0.4 (Kali Linux — Attacker) |
| Target Host | WIN10-Victim.corp.local (10.0.0.20) |
| Credentials Used | CORP\Administrator (from IR-003 DCSync) |
| Event ID | 7045 — New Service Installed |
| Service Pattern | Random 4-char name + random exe in %systemroot% |
| First Event | Jun 9, 2026 @ 17:25:40.898 UTC |
| Last Event | Jun 9, 2026 @ 17:52:32.662 UTC |
| Total Installs | 5 across multiple runs |
| Access Method | SMB port 445 |

---

## 2. Attack Background

PsExec lateral movement works in three stages:

1. **Authentication** — Attacker authenticates to target via SMB using valid credentials
2. **Service Installation** — A randomly named executable is dropped into %systemroot%
   and registered as a Windows service (Event 7045)
3. **Execution** — The service is started, giving the attacker a SYSTEM shell
   on the remote machine

Impacket's PsExec implementation generates a new random service name and
executable name on every run — this is deliberate evasion of signature-based
detection. However the **pattern** remains constant:
- Short random service name (4-5 characters)
- Executable path: %systemroot%\[random].exe
- Service account: LocalSystem
- Start type: demand start

---

## 3. Timeline of Events

| Timestamp | Service Name | Executable | Event |
|-----------|-------------|------------|-------|
| 17:25:40 | mkcL | %systemroot%\rpJRbLTy.exe | First PsExec run |
| 17:29:49 | XmFe | %systemroot%\UNLndNrC.exe | Second run |
| 17:40:36 | fHFX | %systemroot%\bTduATUu.exe | Third run |
| 17:46:15 | fvaa | %systemroot%\BfQbxzlT.exe | Fourth run |
| 17:52:32 | hCDr | %systemroot%\RWmMrAgA.exe | Fifth run |

**Key Observation:** Each run generates a completely new random service name
and executable. No two runs share the same service name — designed to evade
static IOC matching.

---

## 4. Raw Log Evidence

### Event ID 7045 — Service Installation Pattern

```
Event ID:          7045
Service Name:      hCDr / fvaa / fHFX / XmFe / mkcL (random each run)
Service File Name: %systemroot%\RWmMrAgA.exe (random each run)
Service Type:      user mode service
Service Start Type: demand start
Service Account:   LocalSystem
```

### Detection Pattern

| Indicator | Value | Significance |
|-----------|-------|-------------|
| Service name length | 4-5 characters | Random generation pattern |
| ImagePath prefix | %systemroot%\ | Dropped in Windows directory |
| ImagePath suffix | .exe | Executable — not a DLL or service binary |
| Service Account | LocalSystem | Highest privilege level |
| Start Type | demand start | On-demand — not persistent |
| Frequency | 5 installs in 27 minutes | Repeated lateral movement |

---

## 5. KQL Detection Query

### Primary Detection — Random Service Names In %systemroot%

```kql
event.code : "7045"
  and agent.hostname : "WIN10-Victim"
  and not winlog.event_data.ServiceName : (
    "Sysmon64" or "SysmonDrv" or "winlogbeat"
    or "VirtualBox Guest Additions Service" or "VBoxWddm"
    or "Microsoft Defender Core Service"
    or "Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)"
    or "Microsoft Update Health Service"
    or "Printer Extensions and Notifications"
    or "Intel(R) PRO/1000 NDIS 6 Adapter Driver"
  )
```

### Corroborating Query — SMB Authentication Before Service Install

```kql
event.code : "4624"
  and winlog.event_data.LogonType : "3"
  and user.name : "Administrator"
  and agent.hostname : "WIN10-Victim"
```

### Combined Hunt — Full PsExec Kill Chain On Target

```kql
(event.code : "7045" or event.code : "4624")
  and agent.hostname : "WIN10-Victim"
  and (winlog.event_data.LogonType : "3" or winlog.event_data.ImagePath : "%systemroot%*")
```

---

## 6. MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Technique | T1021 — Remote Services |
| Sub-Technique | T1021.002 — SMB/Windows Admin Shares |
| Secondary Technique | T1569.002 — System Services: Service Execution |
| Platform | Windows |
| Data Source | Windows System Event Log (Event 7045) |
| Prerequisite | Valid admin credentials (obtained via IR-003 DCSync) |

---

## 7. Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| Source IP | 10.0.0.4 | Attacker — Kali Linux |
| Target Host | WIN10-Victim (10.0.0.20) | Lateral movement destination |
| Credentials | CORP\Administrator | Obtained from DCSync (IR-003) |
| Protocol | SMB port 445 | Lateral movement vector |
| Service Names | mkcL, XmFe, fHFX, fvaa, hCDr | Random — new each run |
| Executables | rpJRbLTy.exe, UNLndNrC.exe, bTduATUu.exe, BfQbxzlT.exe, RWmMrAgA.exe | Dropped in %systemroot% |
| Tool | Impacket PsExec | Standard lateral movement tool |
| Service Account | LocalSystem | SYSTEM-level execution |

---

## 8. Severity Assessment

**Severity: Critical**

| Factor | Assessment |
|--------|-----------|
| Movement | Attacker now has SYSTEM shell on WIN10-Victim |
| Credentials | Domain Administrator used — highest privilege |
| Technique | SMB — legitimate protocol, hard to block entirely |
| Evasion | Random service names defeat static IOC matching |
| Scope | Attacker can now pivot to any domain-joined machine |
| Link to Chain | Direct consequence of IR-003 DCSync credential dump |

---

## 9. Recommended Response Actions

**Immediate:**
1. Isolate WIN10-Victim from network immediately
2. Terminate all active sessions on WIN10-Victim
3. Search %systemroot% for random named executables:
   ```powershell
   Get-ChildItem C:\Windows\*.exe | Where-Object {$_.Name.Length -le 12}
   ```
4. Delete all PsExec service executables found
5. Reset Administrator password — used for lateral movement

**Short Term:**
1. Block SMB (port 445) between workstations — allow only DC communication
2. Implement Windows Firewall rules restricting lateral SMB:
   ```powershell
   netsh advfirewall firewall add rule name="Block Lateral SMB" dir=in action=block protocol=TCP localport=445 remoteip=10.0.0.0/24
   ```
3. Disable administrative shares (C$, ADMIN$) where not needed
4. Implement Local Administrator Password Solution (LAPS) — unique local admin passwords per machine

**Long Term:**
1. Network segmentation — workstations should not reach other workstations via SMB
2. Deploy Privileged Access Workstations (PAW)
3. Implement Just-In-Time admin access
4. Monitor Event 7045 with threshold alerting — any new service install outside change window

---

## 10. Attack Chain Correlation

```
IR-001: Password Spray → jsmith credentials
IR-002: Kerberoasting → sqlsvc hash
IR-003: DCSync → ALL domain hashes including Administrator
IR-004: LSASS Dump → Local WIN10-Victim credentials
IR-005: PsExec Lateral Movement ← THIS INCIDENT
  └── Administrator credentials from IR-003 used
      5 SYSTEM shells obtained on WIN10-Victim
      Attacker has full control of endpoint
        ↓
IR-006: Pass-the-Hash (next)
IR-007: Scheduled Task Persistence (next)
```

The attacker has now compromised both the Domain Controller (IR-003) and
a domain-joined endpoint (IR-005). The entire domain is under attacker control.

---

## 11. Lessons Learned

1. **Random service names defeat signature detection** — static IOC lists
   are useless against Impacket PsExec. Pattern-based detection (short name +
   %systemroot% path + LocalSystem account) is the correct approach.

2. **Credential reuse across the kill chain** — Administrator credentials
   dumped in IR-003 were immediately weaponised for lateral movement in IR-005.
   This 27-minute gap between DCSync and PsExec shows attacker speed.

3. **SMB firewall rules were missing** — WIN10-Victim accepted inbound SMB
   from any IP including the attacker's Kali machine. Workstation-to-workstation
   SMB should never be permitted.

4. **Event 7045 is undermonitored** — most organisations monitor authentication
   events but ignore service installation events. 7045 with unusual service names
   is a high-fidelity PsExec indicator.

5. **Log shipping delay matters** — events arrived in Kibana 5-10 minutes
   after Windows recorded them. In a real incident this delay could allow
   the attacker additional dwell time before detection.

---

## 12. Tool Reference

**Tool Used:** Impacket PsExec  
**Command:** `impacket-psexec 'corp.local/Administrator:Admin123!@10.0.0.20'`  
**Protocol:** SMB (port 445)  
**Execution Level:** NT AUTHORITY\SYSTEM  
**Evasion:** Random service name + random executable name per run  
**Prerequisite:** Valid administrator credentials + SMB access to target



![Evidence](assets/Pasted%20image%2020260609181056.png)