# Setup Guide 02 — Windows Server 2022 Domain Controller

## VM Specifications

| Setting | Value |
|---------|-------|
| Name | DC01 |
| OS | Windows Server 2022 Standard Evaluation (Desktop Experience) |
| RAM | 4096 MB |
| CPUs | 2 |
| Storage | 50 GB |
| Network | NAT Network → SOC-Lab |

---

## Step 1 — Install Windows Server 2022

1. Create VM in VirtualBox with above specs
2. Attach Windows Server 2022 ISO
3. Boot → Select **Windows Server 2022 Standard Evaluation (Desktop Experience)**
4. Custom install → select empty disk → Next
5. Set Administrator password: `Admin123!`
6. After reboot — remove ISO: **Devices** → **Optical Drives** → **Remove disk**

---

## Step 2 — Configure Static IP

Open PowerShell as Administrator:

```powershell
netsh interface ip set address name="Ethernet" static 10.0.0.10 255.255.255.0 10.0.0.1
netsh interface ip set dns name="Ethernet" static 10.0.0.10
netsh interface ip add dns name="Ethernet" 8.8.8.8 index=2
```

Verify:
```powershell
ipconfig /all
```

Expected: IP 10.0.0.10, DNS 10.0.0.10 + 8.8.8.8, DHCP disabled.

---

## Step 3 — Rename Computer

```powershell
Rename-Computer -NewName "DC01" -Restart
```

---

## Step 4 — Install Active Directory Domain Services

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

---

## Step 5 — Promote to Domain Controller

```powershell
Install-ADDSForest -DomainName "corp.local" -DomainNetbiosName "CORP" -InstallDns -Force
```

Enter SafeModeAdministratorPassword: `Admin123!`

Server restarts automatically. Login as `CORP\Administrator`.

---

## Step 6 — Create OU Structure and Users

```powershell
# Create OUs
New-ADOrganizationalUnit -Name "Corp Users" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "IT" -Path "OU=Corp Users,DC=corp,DC=local"
New-ADOrganizationalUnit -Name "HR" -Path "OU=Corp Users,DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Finance" -Path "OU=Corp Users,DC=corp,DC=local"

# Create domain users
New-ADUser -Name "John Smith" -SamAccountName "jsmith" -UserPrincipalName "jsmith@corp.local" -Path "OU=IT,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Sarah Johnson" -SamAccountName "sjohnson" -UserPrincipalName "sjohnson@corp.local" -Path "OU=HR,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Mike Davis" -SamAccountName "mdavis" -UserPrincipalName "mdavis@corp.local" -Path "OU=Finance,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Emma Wilson" -SamAccountName "ewilson" -UserPrincipalName "ewilson@corp.local" -Path "OU=IT,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Tom Brown" -SamAccountName "tbrown" -UserPrincipalName "tbrown@corp.local" -Path "OU=Finance,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Victim User" -SamAccountName "victim-user" -UserPrincipalName "victim-user@corp.local" -Path "OU=IT,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Add jsmith to Domain Admins (required for DCSync simulation)
Add-ADGroupMember -Identity "Domain Admins" -Members "jsmith"
```

---

## Step 7 — Create Kerberoastable Service Account

```powershell
New-ADUser -Name "SQL Service" -SamAccountName "sqlsvc" -UserPrincipalName "sqlsvc@corp.local" -Path "OU=IT,OU=Corp Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Service123!" -AsPlainText -Force) -Enabled $true
setspn -A MSSQLSvc/DC01.corp.local:1433 sqlsvc
```

---

## Step 8 — Enable Scheduled Task Audit Policy

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

> This is required for Event ID 4698 (scheduled task creation) to be logged.

---

## Verification

```powershell
Get-ADDomain
Get-ADUser -Filter * | Select Name, SamAccountName
setspn -L sqlsvc
```
