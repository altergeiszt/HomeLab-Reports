# Project CSN — VM Build Guide (Tier 2–3 hosts)

Setup instructions for the lab VMs beyond the core three. This covers the **Linux victim**, the **Windows Server domain controller**, the **network detection sensor**, and the **C2 server**. It assumes the SIEM (Elastic + Fleet), attacker (Kali), and Windows 11 victim are already built and running.

> **Choices made here**, matching the roadmap — swap if you prefer:
> - Linux victim → **Ubuntu Server 24.04 LTS** (auditd + Elastic Agent)
> - Domain controller → **Windows Server 2022** (180-day eval)
> - Network sensor → **Zeek + Suricata** on Ubuntu Server, fed by a SPAN/mirror from OPNsense
> - C2 → **Caldera** first (MITRE's own, auto-maps to ATT&CK), Sliver added later

---

## Before you start

**Network.** Put every VM below on the isolated lab VLAN — no route to your home LAN, only the Elastic host reachable for management. OPNsense on the firewall mini PC owns that VLAN. Emulation traffic stays contained and the telemetry stays clean.

**Resource budget (32 GB / 16-thread node).** You will not run all of these at once. Scope each exercise to what it needs and shut the rest down.

| VM | vCPU | RAM | Disk | Runs during |
| --- | --- | --- | --- | --- |
| Linux victim | 2 | 2 GB | 25 GB | Tier 2+ |
| Windows Server DC | 2 | 4 GB | 50 GB | Tier 2+ (AD) |
| Zeek/Suricata sensor | 2 | 2–4 GB | 40 GB | Tier 2+ |
| C2 server | 2 | 2 GB | 20 GB | Tier 3+ |

**Snapshots.** After each VM is built and enrolled, take a clean Proxmox snapshot (and let PBS back it up) so you can revert after a destructive test. Snapshot name convention: `<vm>-clean-<date>`.

**Fleet policy.** In Elastic, create a **separate Agent policy per host type** (`linux-victim`, `domain-controller`) before enrolling, so each host ships the right integrations. You'll paste an enrollment token from Fleet into each install command below.

---

## 1. Linux victim (Ubuntu Server 24.04)

**Purpose.** A Linux endpoint to run the Tier 2a Atomics against — shell execution, cron/SSH persistence, discovery — with auditd and Elastic Agent shipping the telemetry.

### 1.1 Create the VM

1. In Proxmox, create a VM: 2 vCPU, 2 GB RAM, 25 GB disk, on the lab VLAN.
2. Attach the Ubuntu Server 24.04 LTS ISO and install with defaults; create a non-root admin user and enable OpenSSH during install.
3. After first boot: `sudo apt update && sudo apt upgrade -y`.

### 1.2 Install and configure auditd

```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
```

Add a starter rule set aimed at the techniques you'll test (execve, cron, SSH keys, identity files):

```bash
sudo tee /etc/audit/rules.d/csn.rules >/dev/null <<'EOF'
## Command execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
## Cron / scheduling
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
## SSH persistence
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p wa -k home_writes
## Identity / accounts
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
EOF
sudo augenrules --load
sudo auditctl -l   # confirm rules loaded
```

### 1.3 Enroll the Elastic Agent

In Fleet, create/select the `linux-victim` policy, add the **Auditd Logs** (or **Auditd Manager**) and **System** integrations, then copy the Linux enroll command and run it on the victim:

```bash
# From Fleet → Add agent → Linux tar (paste your URL/token/CA)
sudo ./elastic-agent install \
  --url=https://<elastic-host>:8220 \
  --enrollment-token=<token> \
  --certificate-authorities=/path/to/ca.crt
```

### 1.4 Verify and snapshot

- Run `logger "csn test"` and a quick `id; whoami; uname -a`, then confirm the execve/auditd events land in Elastic (filter on the `exec` key).
- Confirm the agent shows **Healthy** in Fleet.
- Take the `linux-victim-clean-<date>` snapshot.

### 1.5 Install Atomic Red Team (Linux)

```bash
# Requires PowerShell for Linux; install pwsh first, then:
pwsh -c "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics"
```

Verify with a benign test (e.g. `Invoke-AtomicTest T1059.004 -ShowDetails`).

---

## 2. Windows Server domain controller (Server 2022)

**Purpose.** Stand up an Active Directory domain so the Tier 2c credential and lateral-movement techniques (Kerberoasting, pass-the-hash, PsExec, DCSync) have somewhere real to run. Join the existing Windows 11 victim to this domain.

### 2.1 Create the VM

1. Proxmox VM: 2 vCPU, 4 GB RAM, 50 GB disk, on the lab VLAN.
2. Install Windows Server 2022 (**Desktop Experience**, 180-day eval) with defaults.
3. Set a static IP on the lab VLAN, set a strong local admin password, rename the host (e.g. `DC01`), reboot.

### 2.2 Promote to a domain controller

Run in an elevated PowerShell:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "csn.lab" -InstallDNS
# You'll be prompted for a DSRM password; the server reboots when done.
```

> Use a lab-only domain name like `csn.lab`. After reboot, `DC01` is the domain controller and DNS server for the lab VLAN.

### 2.3 Seed the domain (so attacks have targets)

```powershell
# A service account with an SPN — the Kerberoasting target
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword (Read-Host -AsSecureString "pw") -Enabled $true
setspn -S MSSQLSvc/DC01.csn.lab:1433 svc_sql
# A couple of ordinary users
New-ADUser -Name "Aaron Analyst" -SamAccountName "aanalyst" -AccountPassword (Read-Host -AsSecureString "pw") -Enabled $true
```

Then **join the Windows 11 victim** to `csn.lab` (System → Rename this PC (advanced) → Domain), and log in once with a domain account so it caches.

### 2.4 Telemetry: Sysmon + Elastic Agent + audit policy

1. Install **Sysmon** with a good config (SwiftOnSecurity or Olaf Hartong's modular config) — same as your Win11 victim.
2. In Fleet, create the `domain-controller` policy with the **Windows**, **System**, and **Sysmon** integrations; enroll the agent (Fleet → Add agent → Windows).
3. Turn on the audit subcategories the AD techniques need:

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
```

> Event references for detections: 4769 (service tickets → Kerberoasting), 4624 type 3 (network logon → PtH), 7045 (service install → PsExec), directory replication (DCSync).

### 2.5 Verify and snapshot

- Confirm the agent is **Healthy** and 4768/4769 events flow into Elastic after a domain login.
- Confirm the Win11 victim is domain-joined (`(Get-WmiObject Win32_ComputerSystem).Domain`).
- Snapshot `DC01-clean-<date>` **and** re-snapshot the Win11 victim now that it's domain-joined.

---

## 3. Network detection sensor (Zeek + Suricata)

**Purpose.** See attacks from the network angle — re-run techniques you already caught on the host and watch them in conn logs and IDS alerts. This is where one attack shows up in two data sources.

### 3.1 Mirror traffic from OPNsense

1. On the OPNsense box, configure a **port mirror / SPAN** (or a mirrored bridge) that copies the lab VLAN's traffic to a dedicated interface.
2. Give the sensor VM **two NICs**: one on the lab VLAN for management (Elastic reachability), one attached to the mirror — set the mirror NIC to **promiscuous mode** in Proxmox and leave it with no IP.

> Alternative if SPAN is awkward: run the sensor inline as a transparent bridge. SPAN is safer for a lab because a sensor crash doesn't drop lab traffic.

### 3.2 Build the VM and install the sensors

1. Proxmox VM: 2 vCPU, 2–4 GB RAM, 40 GB disk, Ubuntu Server 24.04.
2. Install both engines:

```bash
sudo apt update
sudo apt install -y suricata

# Zeek from the official OpenSUSE Build Service repo (24.04):
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | sudo gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
sudo apt update && sudo apt install -y zeek
```

3. Point both at the **mirror interface** (call it `ens19` here — check `ip a`):

```bash
# Suricata
sudo sed -i 's/^\(\s*-\s*interface:\).*/\1 ens19/' /etc/suricata/suricata.yaml
sudo suricata-update            # pull ET Open ruleset
sudo systemctl enable --now suricata

# Zeek
sudo sed -i 's/^interface=.*/interface=ens19/' /opt/zeek/etc/node.cfg
sudo /opt/zeek/bin/zeekctl deploy
```

### 3.3 Ship logs to Elastic

In Fleet, add the **Zeek** and **Suricata** integrations to a policy (a `network-sensor` policy, or reuse one), enroll the Elastic Agent on the sensor, and point the integrations at the log paths (`/opt/zeek/logs/current/` and `/var/log/suricata/eve.json`).

### 3.4 Verify and snapshot

- Generate traffic from Kali (a quick `nmap` against the Win11 victim) and confirm Zeek `conn.log` entries and Suricata alerts appear in Elastic.
- Snapshot `sensor-clean-<date>`.

---

## 4. C2 server (Caldera)

**Purpose.** Move from single techniques to chained operations. Caldera runs adversary emulation that maps to ATT&CK automatically and drops an agent on the Windows victim for you to detect (beaconing, injection, encoded channels).

### 4.1 Build the VM

Proxmox VM: 2 vCPU, 2 GB RAM, 20 GB disk, Ubuntu Server 24.04, on the lab VLAN.

> **Isolation matters here.** This VM runs offensive tooling. Keep it on the lab VLAN only, and never give it a route to your home network.

### 4.2 Install Caldera

```bash
sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt --break-system-packages
python3 server.py --insecure    # first run; note the printed admin/red passwords
```

Reach the web UI at `https://<c2-ip>:8888` from within the lab. Change the default credentials in `conf/local.yml` before real use.

### 4.3 Deploy an agent to the Windows victim

1. In the Caldera UI: **Agents → Deploy an agent → Sandcat (54ndc47)**.
2. Copy the generated PowerShell one-liner and run it on the **Windows 11 victim** (from an elevated prompt) to plant the beacon.
3. Confirm the agent checks in under **Agents**.

### 4.4 First operation (Tier 3a)

Run a small built-in operation (e.g. *Discovery*) against the agent, then pivot to Elastic and confirm you can see:

- the beaconing / callback pattern (host + Zeek),
- any process injection (Sysmon event 8/10),
- the encoded C2 channel on the wire.

### 4.5 Snapshot and (later) Sliver

- Snapshot `c2-clean-<date>` once Caldera is working.
- When you want a more realistic implant and operator experience, add **Sliver** on the same VM (or a second one) and repeat the detect-the-implant exercises.

---

## Build order checklist

- [ ] Lab VLAN confirmed isolated (no route to home LAN)
- [ ] Fleet policies created: `linux-victim`, `domain-controller`, `network-sensor`
- [ ] **Linux victim** built, auditd + Agent healthy, ART installed, snapshot taken
- [ ] **Domain controller** promoted (`csn.lab`), seeded, Win11 joined, audit policy on, snapshots taken (DC + re-snapshot Win11)
- [ ] **Network sensor** mirroring OPNsense, Zeek + Suricata shipping to Elastic, snapshot taken
- [ ] **C2 server** running Caldera, agent checks in from Win11, snapshot taken

Once these are green, the Tier 2 and Tier 3 exercises in the roadmap all have the infrastructure they need.


C11366D1178003B86C8F43776F90D89420EB800E8589A129E1D206488BC45EE1