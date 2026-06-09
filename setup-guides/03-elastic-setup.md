# Setup Guide 03 — Elastic Stack (Elasticsearch + Kibana)

## VM Specifications

| Setting | Value |
|---------|-------|
| Name | Elastic-SIEM |
| OS | Ubuntu Server 22.04 LTS |
| RAM | 6144 MB |
| CPUs | 4 |
| Storage | 80 GB |
| Network | NAT Network → SOC-Lab |

---

## Step 1 — Install Ubuntu Server 22.04

1. Create VM in VirtualBox with above specs
2. Attach Ubuntu Server 22.04 ISO
3. Boot → Continue without updating installer
4. Select **Ubuntu Server** (not minimized)
5. Network: confirm DHCP assigns 10.0.0.5
6. Storage: use entire disk with LVM
7. Profile setup:
   - Name: `soc-admin`
   - Server name: `elastic-siem`
   - Username: `soc-admin`
   - Password: `Password123!`
8. Install OpenSSH Server: ✅
9. Snaps: select nothing
10. Reboot → remove ISO when prompted

---

## Step 2 — Configure Static IP

SSH in from host:
```powershell
ssh soc-admin@127.0.0.1 -p 2222
```

Set static IP:
```bash
sudo tee /etc/netplan/50-cloud-init.yaml << 'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.0.5/24
      routes:
        - to: default
          via: 10.0.0.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
EOF
sudo netplan apply
```

Verify: `ip a` → should show 10.0.0.5

---

## Step 3 — Install Elasticsearch 8.19.16

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update && sudo apt install -y elasticsearch
```

> **IMPORTANT:** Copy the auto-generated elastic password from the installation output before proceeding.

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
```

---

## Step 4 — Install Kibana 8.19.16

```bash
sudo apt install -y kibana
```

Configure Kibana to listen on all interfaces:
```bash
sudo nano /etc/kibana/kibana.yml
```

Find `#server.host: "localhost"` and change to:
```
server.host: "0.0.0.0"
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable kibana.service
sudo systemctl start kibana.service
```

---

## Step 5 — Connect Kibana to Elasticsearch

Generate enrollment token:
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```

Add Kibana port forwarding in VirtualBox Network Manager:

| Field | Value |
|-------|-------|
| Name | Kibana |
| Protocol | TCP |
| Host Port | 5601 |
| Guest IP | 10.0.0.5 |
| Guest Port | 5601 |

Open browser → `http://127.0.0.1:5601` → paste enrollment token.

Get verification code:
```bash
sudo /usr/share/kibana/bin/kibana-verification-code
```

Login: username `elastic`, password from installation output.

---

## Step 6 — Run Winlogbeat Setup (after Winlogbeat installed on Windows VMs)

This step is completed after Winlogbeat is installed on DC01 and WIN10-Victim:

```powershell
cd C:\winlogbeat\winlogbeat
.\winlogbeat.exe setup -c winlogbeat.yml
```

---

## Credentials

| Service | Username | Password |
|---------|----------|----------|
| Ubuntu Server | soc-admin | Password123! |
| Elasticsearch | elastic | [auto-generated during install] |

---

## Verification

```bash
sudo systemctl status elasticsearch
sudo systemctl status kibana
```

Both should show **active (running)**.

Browser: `http://127.0.0.1:5601` → login → Stack Management → Index Management → Data Streams → verify `winlogbeat-8.19.16` appears after Winlogbeat is configured.
