# Setup Guide 01 — VirtualBox NAT Network

## Prerequisites
- Oracle VirtualBox 7.1 installed
- Downloaded ISOs:
  - Windows Server 2022 Evaluation (.iso)
  - Windows 10 (.iso)
  - Ubuntu Server 22.04 LTS (.iso)
  - Kali Linux 2026.x VirtualBox image (.vbox + .vdi)

---

## Step 1 — Create SOC-Lab NAT Network

1. Open VirtualBox
2. **File** → **Tools** → **Network Manager**
3. Click **NAT Networks** tab → **Create**
4. Configure:

| Setting | Value |
|---------|-------|
| Name | SOC-Lab |
| IPv4 Prefix | 10.0.0.0/24 |
| Enable DHCP | ✅ |
| Enable IPv6 | ❌ |

5. Click **Apply**

---

## Step 2 — Import Kali Linux

1. VirtualBox → **Machine** → **Add**
2. Navigate to Kali .vbox file → **Open**
3. Select Kali VM → **Settings** → **Network** → **Adapter 1**:
   - Attached to: **NAT Network**
   - Name: **SOC-Lab**
4. Click **OK**

---

## Step 3 — Install Kali Guest Additions

Boot Kali (credentials: kali/kali), open terminal:

```bash
sudo apt update && sudo apt install -y virtualbox-guest-x11
sudo reboot
```

Enable clipboard: VirtualBox menu → **Devices** → **Shared Clipboard** → **Bidirectional**

---

## Step 4 — Verify Kali Network

```bash
ip a
ping -c 4 google.com
```

Expected: IP **10.0.0.4/24**, successful ping.

---

## Step 5 — SSH Port Forwarding (for Ubuntu Server)

After Ubuntu is installed, add this rule in Network Manager → SOC-Lab → Port Forwarding:

| Field | Value |
|-------|-------|
| Name | SSH-Ubuntu |
| Protocol | TCP |
| Host IP | 0.0.0.0 |
| Host Port | 2222 |
| Guest IP | 10.0.0.5 |
| Guest Port | 22 |

Connect from host:
```powershell
ssh soc-admin@127.0.0.1 -p 2222
```

---

## VM IP Reference

| VM | Role | IP |
|----|------|----|
| Kali Linux | Attacker | 10.0.0.4 (DHCP) |
| Ubuntu Server | Elastic SIEM | 10.0.0.5 (Static) |
| Windows Server 2022 | DC01 | 10.0.0.10 (Static) |
| Windows 10 | WIN10-Victim | 10.0.0.20 (Static) |
