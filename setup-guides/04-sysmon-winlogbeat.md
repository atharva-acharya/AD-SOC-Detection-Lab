# Setup Guide 04 — Sysmon + Winlogbeat (Windows VMs)

Apply this guide to **both DC01 and WIN10-Victim**.

---

## Part A — Install Sysmon v15.20

Run in PowerShell as Administrator on each Windows VM:

### Step 1 — Download Sysmon

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
```

### Step 2 — Extract

```powershell
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"
```

### Step 3 — Download Olaf Hartong Config

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
```

### Step 4 — Install Sysmon

```powershell
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Step 5 — Verify

```powershell
Get-Service Sysmon64
```

Expected: **Running**

---

## Part B — Install Winlogbeat 8.19.16

### Step 1 — Download

```powershell
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.16-windows-x86_64.zip" -OutFile "C:\winlogbeat.zip"
```

### Step 2 — Extract and Rename

```powershell
Expand-Archive -Path "C:\winlogbeat.zip" -DestinationPath "C:\winlogbeat"
Rename-Item "C:\winlogbeat\winlogbeat-8.19.16-windows-x86_64" "C:\winlogbeat\winlogbeat"
```

---

## Part C — Configure Winlogbeat

```powershell
notepad C:\winlogbeat\winlogbeat\winlogbeat.yml
```

Replace entire contents with:

```yaml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Windows PowerShell
    event_id: 400, 403, 600, 800
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106

output.elasticsearch:
  hosts: ["https://10.0.0.5:9200"]
  username: "elastic"
  password: "<your-elastic-password>"
  ssl.verification_mode: none
  pipeline: "winlogbeat-%{[agent.version]}-routing"

setup.kibana:
  host: "http://10.0.0.5:5601"

setup.template.settings:
  index.number_of_shards: 1

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
```

> Replace `<your-elastic-password>` with the password generated during Elasticsearch installation.

---

## Part D — Install and Start Winlogbeat Service

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
cd C:\winlogbeat\winlogbeat
.\install-service-winlogbeat.ps1
.\winlogbeat.exe setup -c winlogbeat.yml
Start-Service winlogbeat
Get-Service winlogbeat
```

Expected: **Running**

---

## Part E — Enable Audit Policy for Scheduled Task Detection

> Run on WIN10-Victim only — required for Event ID 4698 detection

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

---

## Verification — Confirm Logs Flowing

1. Open browser → `http://127.0.0.1:5601`
2. Hamburger menu → **Discover**
3. Select **winlogbeat-\*** data view
4. Filter: `agent.hostname : "DC01"` → should show events
5. Filter: `agent.hostname : "WIN10-Victim"` → should show events

---

## Sysmon Events Monitored

| Event ID | Description | Key Attacks Detected |
|----------|-------------|---------------------|
| 1 | Process Creation | PsExec service execution |
| 3 | Network Connection | C2 beaconing |
| 7 | Image Load | DLL hijacking |
| 8 | CreateRemoteThread | Process injection |
| 10 | ProcessAccess | LSASS dumping |
| 22 | DNS Query | DNS tunneling |

## Windows Security Events Monitored

| Event ID | Description | Key Attacks Detected |
|----------|-------------|---------------------|
| 4624 | Successful Logon | Pass-the-Hash (NTLM) |
| 4625 | Failed Logon | Password Spraying |
| 4662 | Object Operation | DCSync |
| 4698 | Scheduled Task Created | Persistence |
| 4769 | Kerberos TGS Request | Kerberoasting |
| 7045 | New Service Installed | PsExec Lateral Movement |
