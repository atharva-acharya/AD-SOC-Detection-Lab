# CV Project Description

## For CV / Resume

**Active Directory SOC Detection Lab** | Elastic SIEM, Sysmon, KQL, MITRE ATT&CK | [GitHub Link]

Built a 4-VM enterprise Active Directory environment to simulate and detect 7 real-world attack
scenarios including DCSync, Kerberoasting, Pass-the-Hash, and LSASS dumping. Deployed Elastic
Stack 8.19.16 with Sysmon telemetry, wrote KQL detection rules for each attack mapped to MITRE
ATT&CK, and documented findings as 7 formal SOC investigation reports covering alert triage,
IOC identification, and recommended response actions.

---

## For LinkedIn Project Section (longer version)

**Active Directory SOC Detection Lab**

Built a full enterprise-grade SOC detection environment from scratch using VirtualBox, simulating
a small corporate AD environment (Windows Server 2022 DC, Windows 10 endpoint, Kali Linux attacker)
with Elastic Stack 8.19.16 as the SIEM.

Simulated and detected 7 attack scenarios across the full kill chain:
- Credential Access: Password Spraying, Kerberoasting, DCSync, LSASS Dump
- Lateral Movement: PsExec, Pass-the-Hash
- Persistence: Scheduled Task

For each attack: executed from Kali, observed raw telemetry in Kibana, wrote KQL detection rules,
and produced a formal SOC investigation report including alert summary, timeline, raw log evidence,
MITRE ATT&CK mapping, IOCs, severity assessment, and recommended response actions.

Detection stack: Sysmon v15.20 (Olaf Hartong config) + Winlogbeat 8.19.16 + Elastic SIEM.
Coverage visualised on MITRE ATT&CK Navigator v19.

Key technical skills demonstrated: KQL query writing, Windows Event ID analysis (4624/4625/4662/
4698/4769/7045), Sysmon Event 10 (LSASS detection), Active Directory architecture, log pipeline
engineering, SOC investigation documentation.

---

## For Cover Letter (one sentence)

"I recently built a 4-VM Active Directory SOC detection lab where I simulated and detected 7
enterprise attack scenarios including DCSync and Pass-the-Hash using Elastic SIEM, producing
formal investigation reports for each — demonstrating hands-on readiness to contribute to a
SOC from day one."

---

## GitHub Repository Name Suggestion

`AD-SOC-Detection-Lab`

## GitHub Description (one line)

`4-VM Active Directory lab simulating 7 enterprise attacks with Elastic SIEM detections, KQL rules, and formal SOC investigation reports mapped to MITRE ATT&CK.`

## GitHub Topics/Tags

`soc` `elastic-siem` `active-directory` `kql` `sysmon` `mitre-attack` `blue-team` `incident-response` `threat-detection` `windows-security`
