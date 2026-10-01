# Project CSN — VM Build Guide v3 (Tier 2–3 hosts)

Setup instructions for the lab VMs beyond the core three. This covers the **Linux victim**, the **Windows Server domain controller**, the **network detection sensor**, and the **C2 server**. It assumes the SIEM (Elastic + Fleet), attacker (Kali), and Windows 11 victim are already built and running.

> **What changed from v2**
> - **Section 3 rewritten.** OPNsense has no port-mirror feature and only sees traffic that crosses it, so the SPAN in v2 step 3.1 cannot work. The mirror now lives on the Proxmox host (`tc` mirroring from victim taps to an isolated capture bridge, `vmbr2`).
> - Sensor steps are written from a verified build: capture NIC matched by MAC (not assumed to be `ens19`), safe-to-rerun config edits for Suricata, Zeek JSON logging (required by the Elastic Zeek integration), boot services, log retention, and Fleet enrollment.
> - "Before you start" and the build checklist updated to match. Sections 1, 2 and 4 are unchanged from v2.

> **Choices made here**, matching the roadmap — swap if you prefer:
> - Linux victim → **Ubuntu Server 24.04 LTS** (auditd + Elastic Agent)
> - Domain controller → **Windows Server 2022** (180-day eval)
> - Network sensor → **Zeek + Suricata** on Ubuntu Server, fed by a Proxmox `tc` mirror of the victim VMs' tap interfaces onto an isolated capture bridge
> - C2 → **Caldera** first (MITRE's own, auto-maps to ATT&CK), Sliver added later

---

## Before you start

**Network.** OPNsense runs as a VM on the Proxmox node (VM 200 in this lab) and owns the lab bridge `vmbr1`. Put every VM below on `vmbr1`. Outbound internet works through OPNsense (needed for `apt` and rule downloads); what must **not** work is any route to your home LAN. Verify that before building anything (ping a home LAN device from a lab VM; it should fail).

**Lab VM IDs used in this guide.** Substitute your own.

| VM | ID |
| --- | --- |
| elastic-siem | 100 |
| kali-vm | 101 |
| win11-victim | 102 |
| ubuntu-victim | 103 |
| opnsense | 200 |
| zeeksuricata (sensor) | 201 |

**Resource budget (32 GB / 16-thread node).** You will not run all of these at once. Scope each exercise to what it needs and shut the rest down.

| VM | vCPU | RAM | Disk | Runs during |
| --- | --- | --- | --- | --- |
| Linux victim | 2 | 2 GB | 25 GB | Tier 2+ |
| Windows Server DC | 2 | 4 GB | 50 GB | Tier 2+ (AD) |
| Zeek/Suricata sensor | 2 | 4 GB | 40 GB | Tier 2+ |
| C2 server | 2 | 2 GB | 20 GB | Tier 3+ |

**Snapshots.** After each VM is built and enrolled, take a clean Proxmox snapshot (and let PBS back it up) so you can revert after a destructive test. Snapshot name convention: `<vm>-clean-<date>`.

**Fleet policy.** In Elastic, create a **separate Agent policy per host type** (`linux-victim`, `domain-controller`, `network-sensor`) before enrolling, so each host ships the right integrations. Grab each host's enrollment token from **Fleet → Agents → Add agent** with the matching policy selected, and paste it into the install command for that host.

### A note on Fleet TLS and `--insecure`

Every enroll command below uses `--insecure`, on purpose. We checked this lab's setup (Sept 2026): Fleet Server runs as an Elastic-Agent component on the `elastic-siem` host (`10.10.10.176:8220`) and presents a **self-signed cert** (`issuer O=elastic-fleet, CN=localhost`, `subject CN=elastic-siem`). There is **no CA file written to disk** to reuse — the TLS material is held internally by the managed agent, not exported as a `.crt`. So there's nothing to pass to `--certificate-authorities`, and the Win11 victim was enrolled the same way.

`--insecure` means the agent does **not verify** Fleet Server's certificate. It does **not** turn off encryption — the agent↔Fleet channel is still TLS. On an isolated lab VLAN with no route to anything else, that's a fair trade.

> **If you ever want to do it properly** (a good hygiene exercise): re-run Fleet Server setup with a real CA and the host's IP/DNS in the cert's SAN, distribute that CA to every agent, and drop `--insecure`. Not required to get the lab running.

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
# From Fleet → Add agent → Linux tar. Get the enrollment token from
# Fleet → Agents → Add agent (pick the linux-victim policy).
sudo ./elastic-agent install \
  --url=https://10.10.10.176:8220 \
  --enrollment-token=<linux-victim-token> \
  --insecure
```

> `--insecure` skips verification of Fleet Server's TLS cert — it does **not** disable encryption; the agent↔Fleet channel is still TLS. We use it because Fleet presents a self-signed cert and there's no reusable CA file on disk (see [Fleet TLS note](#a-note-on-fleet-tls-and---insecure)). Fine for an isolated lab VLAN.

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
2. In Fleet, create the `domain-controller` policy with the **Windows**, **System**, and **Sysmon** integrations, then enroll the agent from an elevated PowerShell (Fleet → Add agent → Windows for the download step; token from Fleet → Agents → Add agent, `domain-controller` policy):

   ```powershell
   .\elastic-agent.exe install `
     --url=https://10.10.10.176:8220 `
     --enrollment-token=<dc-token> `
     --insecure
   ```

   Same `--insecure` reasoning as the Linux victim — see the [Fleet TLS note](#a-note-on-fleet-tls-and---insecure).
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

Lab IDs used below: sensor = VM 201, win11-victim = VM 102. Substitute your own.

### 3.1 How the mirror works (and why it is not on OPNsense)

OPNsense has no port-mirror feature, and it only sees traffic that **crosses** it. Lab hosts share one subnet on `vmbr1`, so host-to-host traffic (Kali → victim) stays on the bridge and never reaches the firewall. A mirror at OPNsense would miss most of what this sensor exists to see.

So the mirror lives on the Proxmox host. Each monitored VM's **tap interface** is copied with `tc` onto the sensor's capture tap:

- `vmbr1` is the existing lab bridge.
- `vmbr2` is a **new bridge with no ports and no physical NIC**. It exists only to carry the sensor's capture NIC, so mirrored frames never touch the lab network and cannot loop.
- **Mirror the victims only.** Do not mirror Kali (every Kali → victim packet would appear twice), the Elastic host (agent noise), or the sensor's own taps.

> LXC containers use `veth<ID>i<N>` interfaces instead of `tap<ID>i<N>`. This guide uses VMs.

### 3.2 Capture bridge and sensor NICs

1. On the Proxmox host, add to `/etc/network/interfaces`:

   ```
   auto vmbr2
   iface vmbr2 inet manual
       bridge-ports none
       bridge-stp off
       bridge-fd 0
   ```

   Then apply it:

   ```bash
   ifreload -a
   ```

   (GUI alternative: Node → System → Network → Create → Linux Bridge, name `vmbr2`, no ports, Apply Configuration.)

2. Create the sensor VM (Ubuntu Server, 2 vCPU, 4 GB RAM, 40 GB disk) with:
   - a **management NIC** on `vmbr1` (Elastic reachability, SSH);
   - a **capture NIC** on `vmbr2` with **Firewall unchecked**.

   If the capture NIC is added to an existing VM:

   ```bash
   qm set 201 --net2 virtio,bridge=vmbr2,firewall=0
   ```

   > NIC numbering depends on how the VM was created. In this lab the management NIC is `net1` and the capture NIC is `net2`, so the capture tap is **`tap201i2`**. On a fresh VM built with management as `net0`, capture will be `net1` and the tap `tap201i1`. Check `qm config 201 | grep -E '^net'` and use your own tap name everywhere below.

3. Start the sensor VM (the tap exists only while the VM runs).

**Test 3.2 (pass/fail).** On the Proxmox host:

```bash
qm config 201 | grep -E '^net'
ip -br link show vmbr2
bridge link show master vmbr2
```

- **Pass:** the capture NIC shows `bridge=vmbr2` with no `firewall=1`; `vmbr2` is up; `bridge link` lists exactly one port, the sensor's capture tap. (`UNKNOWN` state on a bridge is normal.)
- **Fail:** any other port on `vmbr2`, or none.

### 3.3 Mirror rules

Find the tap names (VMs must be running):

```bash
qm config 102 | grep -E '^net'
ip -br link | grep -E 'tap(102|201)'
```

Mirror both directions of the victim's tap to the capture tap:

```bash
# Traffic FROM the victim (ingress on its tap)
tc qdisc add dev tap102i0 handle ffff: ingress
tc filter add dev tap102i0 parent ffff: protocol all matchall action mirred egress mirror dev tap201i2

# Traffic TO the victim (egress on its tap)
tc qdisc add dev tap102i0 handle 1: root prio
tc filter add dev tap102i0 parent 1: protocol all matchall action mirred egress mirror dev tap201i2
```

To remove the mirror:

```bash
tc qdisc del dev tap102i0 ingress
tc qdisc del dev tap102i0 root
```

**Test 3.3 (pass/fail).** On the host: `apt install -y tcpdump`, then

```bash
tcpdump -ni tap201i2 -c 8 icmp
```

and from the victim run `ping 10.10.10.1` (OPNsense).

- **Pass:** 4 echo requests `10.10.10.186 → 10.10.10.1` and 4 replies back, 8 packets, 0 dropped.
- **Partial:** one direction only — check `tc filter show dev tap102i0 ingress` and `tc filter show dev tap102i0 parent 1:`.

> Always filter (`icmp`) for this test. The victim's own Elastic Agent traffic will fill an unfiltered capture before your ping runs.
> Use `parent 1:` (not `root`) to display the egress filter.

### 3.4 Make the mirror survive restarts

The `tc` rules disappear whenever a tap is recreated (any Proxmox stop/start of the victim **or** the sensor). A hookscript rebuilds them. Restarting the sensor also breaks the victim's rule, because it points at the old tap, so attach the script to **both**.

1. Confirm a storage allows snippets:

   ```bash
   pvesm status --content snippets
   ```

   If `local` is not listed, enable **Snippets** under Datacenter → Storage → local → Edit → Content (keep the existing types ticked).

2. Create the script:

   ```bash
   tee /var/lib/vz/snippets/csn-mirror.sh >/dev/null <<'EOF'
   #!/bin/bash
   # Project CSN: mirror victim taps to the sensor capture NIC.
   PHASE="$2"
   SENSOR_TAP="tap201i2"
   VICTIM_TAPS="tap102i0"   # add more later, space-separated (e.g. tap103i0)

   [ "$PHASE" = "post-start" ] || exit 0
   ip link show "$SENSOR_TAP" >/dev/null 2>&1 || exit 0   # sensor off: its own start will apply the rules

   for t in $VICTIM_TAPS; do
     ip link show "$t" >/dev/null 2>&1 || continue
     tc qdisc del dev "$t" ingress 2>/dev/null
     tc qdisc del dev "$t" root 2>/dev/null
     tc qdisc add dev "$t" handle ffff: ingress
     tc filter add dev "$t" parent ffff: protocol all matchall action mirred egress mirror dev "$SENSOR_TAP"
     tc qdisc add dev "$t" handle 1: root prio
     tc filter add dev "$t" parent 1: protocol all matchall action mirred egress mirror dev "$SENSOR_TAP"
     logger -t csn-mirror "mirrored $t -> $SENSOR_TAP"
   done
   exit 0
   EOF
   chmod +x /var/lib/vz/snippets/csn-mirror.sh
   qm set 102 --hookscript local:snippets/csn-mirror.sh
   qm set 201 --hookscript local:snippets/csn-mirror.sh
   ```

   The script is safe to re-run by hand: `/var/lib/vz/snippets/csn-mirror.sh 0 post-start`. As you build more victims (Linux victim, DC), add their taps to `VICTIM_TAPS` and run `qm set <vmid> --hookscript local:snippets/csn-mirror.sh` on each.

**Test 3.4 (pass/fail).**

```bash
qm config 102 | grep hookscript
qm config 201 | grep hookscript
```

Restart the victim, then check:

```bash
qm shutdown 102        # wait for "stopped" in qm list
qm start 102
sleep 5
tc filter show dev tap102i0 ingress
tc filter show dev tap102i0 parent 1:
journalctl -t csn-mirror -n 3 --no-pager
```

Then restart the sensor and repeat the same three check commands:

```bash
qm stop 201
qm start 201
sleep 5
```

- **Pass (both restarts):** both `tc` outputs show `mirred (Egress Mirror to device tap201i2)`, and the journal has a fresh `mirrored tap102i0 -> tap201i2` line after each restart.

### 3.5 Sensor OS: the capture NIC

Inside the sensor VM, identify the capture NIC **by MAC address**, not by name. Interface names depend on PCI slot order; in this lab the management NIC is `ens19` and the capture NIC is `ens20`.

```bash
# On the Proxmox host:
qm config 201 | grep -E '^net'
# Inside the sensor VM:
ip -br link
ip -br addr
```

The capture NIC is the interface whose MAC matches the capture NIC in `qm config`. It must have **no IP address** (it may show `DOWN` for now).

Bring it up promiscuous with IPv6 off and offloads off, persistently (replace `ens20` with your capture NIC name):

```bash
sudo apt install -y ethtool tcpdump

sudo tee /etc/systemd/system/csn-capture-nic.service >/dev/null <<'EOF'
[Unit]
Description=CSN capture NIC setup (ens20)
After=sys-subsystem-net-devices-ens20.device
Requires=sys-subsystem-net-devices-ens20.device

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.ens20.disable_ipv6=1
ExecStart=/usr/sbin/ip link set ens20 promisc on up
ExecStart=-/usr/sbin/ethtool -K ens20 gro off lro off tso off gso off

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now csn-capture-nic.service
```

The `-` before the `ethtool` line stops the service failing if the virtio driver reports a feature as fixed. Turning offloads off matters: otherwise the sensor receives merged oversized frames and frames with unfilled checksums.

**Test 3.5 (pass/fail).**

```bash
ip -br link show ens20
ip -br addr show ens20
ethtool -k ens20 | grep -E 'generic-receive-offload|large-receive-offload|tcp-segmentation-offload|generic-segmentation-offload'
```

- **Pass:** `UP` with `PROMISC`, no address, every offload line `off` (`off [fixed]` is fine). Reboot the sensor and confirm the same with no manual steps.

**Test 3.5b — mirrored frames reach the guest.** In the sensor run `sudo tcpdump -ni ens20 -c 8 icmp`, then `ping 10.10.10.1` from the victim.

- **Pass:** 4 requests and 4 replies between `10.10.10.186` and `10.10.10.1`.

### 3.6 Suricata

```bash
sudo apt update
sudo apt install -y suricata
suricata -V
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.orig
```

> Do **not** use a blanket `sed` on `- interface:`. `suricata.yaml` has several such lines (including a `default` entry) and a blanket edit produces duplicates. The edits below target one line each and are safe to re-run. `suricata.yaml.orig` is your undo.

**1. Capture interface** (the first `af-packet` entry; default is `eth0`):

```bash
sudo sed -i '/^af-packet:/{n;s/interface: .*/interface: ens20/}' /etc/suricata/suricata.yaml
sudo grep -n -A1 '^af-packet:' /etc/suricata/suricata.yaml
```

**2. Checksums.** Mirrored frames often carry checksums the host has not filled in yet, and Suricata would treat them as invalid. Turn validation off for the capture entry:

```bash
sudo sed -i 's/^\(\s*\)#checksum-checks: kernel/\1checksum-checks: no/' /etc/suricata/suricata.yaml
sudo grep -n 'checksum-checks: no' /etc/suricata/suricata.yaml
```

Confirm the match is inside the `ens20` `af-packet` entry (its line number is before the later `- interface: default` entries). Other `checksum-checks` lines belong to other capture modes; leave them.

**3. `EXTERNAL_NET`.** The default is `!$HOME_NET`, and `HOME_NET` includes `10.0.0.0/8`, so lab attackers count as "home" and many ET rules (which match traffic from `$EXTERNAL_NET`) would never fire on them. Set it to `any`:

```bash
sudo sed -i -e 's/^\(\s*\)EXTERNAL_NET: "!\$HOME_NET"/\1#EXTERNAL_NET: "!$HOME_NET"/' \
            -e 's/^\(\s*\)#EXTERNAL_NET: "any"/\1EXTERNAL_NET: "any"/' /etc/suricata/suricata.yaml
sudo grep -n 'EXTERNAL_NET' /etc/suricata/suricata.yaml | head -3
```

> Trade-off: more alerts on lab-internal traffic, which is what you want here, since every attacker in this lab is internal.

**4. Load rules and test the config:**

```bash
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
```

- **Pass:** `suricata-update` reports ET Open rules loaded (roughly 69,000 loaded, 53,000 enabled in this lab), and the config test ends with `Configuration provided was successfully loaded. Exiting.`

**5. Start it and confirm it is capturing on the capture NIC:**

```bash
systemctl cat suricata | grep ExecStart
sudo systemctl enable --now suricata
sleep 15
systemctl is-active suricata
sudo tail -n 8 /var/log/suricata/suricata.log
sudo grep 'capture.kernel_packets' /var/log/suricata/stats.log | tail -2
```

- **Pass:** `active`; the `ExecStart` line does not override the interface; the log shows `ens20: creating 2 threads` and no `Error` lines; `capture.kernel_packets` rises between readings.

> `systemctl is-active` prints `active` even when rules failed to load. The config test (`suricata -T`) and `suricata.log` (`rules successfully loaded, 0 rules failed`) are the checks that matter.

**6. Prove alerts fire with a local test rule** (the lab has no need for `testmyids.com`):

```bash
sudo tee /var/lib/suricata/rules/local.rules >/dev/null <<'EOF'
alert icmp any any -> any any (msg:"CSN TEST ICMP echo request"; itype:8; sid:9000001; rev:1;)
EOF

# Register it exactly once (safe to re-run; a duplicate entry makes Suricata reject the rule):
grep -q '^  - local\.rules$' /etc/suricata/suricata.yaml || sudo sed -i '/^  - suricata\.rules$/a\  - local.rules' /etc/suricata/suricata.yaml
sudo grep -n -A3 '^rule-files:' /etc/suricata/suricata.yaml

sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | tail -3
sudo systemctl restart suricata
sleep 20
sudo grep -c 9000001 /var/log/suricata/fast.log     # note the count
```

Ping `10.10.10.1` from the victim, wait about 5 seconds, then:

```bash
sudo grep -c 9000001 /var/log/suricata/fast.log
sudo grep 9000001 /var/log/suricata/fast.log | tail -4
```

- **Pass:** `rule-files:` lists `local.rules` exactly once; the config test has no `E:` lines; the count rises by exactly **4**; the alerts show `CSN TEST ICMP echo request` from `10.10.10.186` to `10.10.10.1`. Exactly 4 (not 8) confirms each mirrored packet reaches Suricata once.

### 3.7 Zeek

Zeek comes from the OpenSUSE Build Service repository. The key goes in a dedicated keyring file and is trusted for this repo only:

```bash
echo 'deb [signed-by=/usr/share/keyrings/security_zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | sudo gpg --dearmor -o /usr/share/keyrings/security_zeek.gpg
sudo apt update
sudo apt install -y zeek
/opt/zeek/bin/zeek --version
sudo cat /opt/zeek/etc/node.cfg
```

> The `xUbuntu_24.04` repo directory also worked on the newer Ubuntu release this lab's sensor runs (Zeek 9.0.0). If `apt` cannot resolve dependencies on your release, look for a matching directory on the OBS repository page.

**Configure** (replace `ens20` with your capture NIC):

```bash
sudo sed -i 's/^interface=.*/interface=ens20/' /opt/zeek/etc/node.cfg

# Ignore checksums (same offload issue as Suricata)
grep -q 'ignore_checksums' /opt/zeek/share/zeek/site/local.zeek || echo 'redef ignore_checksums = T;' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek

# JSON logs: REQUIRED by the Elastic Zeek integration (it only parses JSON)
grep -q 'json-logs' /opt/zeek/share/zeek/site/local.zeek || echo '@load policy/tuning/json-logs.zeek' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek

# zeekctl netstats needs this Python module
sudo apt install -y python3-websockets

sudo /opt/zeek/bin/zeekctl check
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

**Start Zeek at boot.** `zeekctl deploy` alone does not survive a reboot. This unit starts Zeek after the capture NIC service, so the interface exists and is promiscuous first:

```bash
sudo tee /etc/systemd/system/csn-zeek.service >/dev/null <<'EOF'
[Unit]
Description=CSN Zeek (zeekctl)
After=csn-capture-nic.service
Requires=csn-capture-nic.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=120
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now csn-zeek.service
systemctl is-active csn-zeek.service
```

**Test 3.7 (pass/fail).**

1. `interface=ens20` is the only active interface line; `zeekctl check` says `zeek scripts are ok`; the `zeek` node is `running`; no `UseWebSocket` warning.
2. Ping `10.10.10.1` from the victim, wait about 2 minutes (Zeek logs an ICMP connection only when it times out), then:

   ```bash
   sudo ls /opt/zeek/logs/current/
   sudo head -n 1 /opt/zeek/logs/current/conn.log
   sudo grep icmp /opt/zeek/logs/current/conn.log | grep 10.10.10.186 | tail -2
   sudo /opt/zeek/bin/zeekctl netstats
   ```

   - **Pass:** the first line of `conn.log` starts with `{` (JSON; a `#separator` header means it is still tab-separated); a fresh ICMP row shows `10.10.10.186 → 10.10.10.1` with 4 packets each way; `netstats` shows a nonzero `recvd` with `dropped=0`.
3. Reboot the sensor. Then `systemctl is-active csn-capture-nic.service csn-zeek.service` prints `active` twice, `ens20` shows `PROMISC`, and the Zeek `Started` time is after the reboot.

### 3.8 Log retention

Both engines write continuously, and the sensor disk is small. Zeek keeps logs forever by default and only deletes them when `zeekctl cron` runs; Suricata's rotation is triggered by the system logrotate timer.

```bash
df -h /
sudo du -sh /opt/zeek/logs /var/log/suricata

# Zeek: expire logs after 14 days, and run zeekctl cron every 5 minutes
# (cron also restarts Zeek if it crashes)
sudo apt install -y cron logrotate
sudo sed -i 's/^LogExpireInterval *=.*/LogExpireInterval = 14/' /opt/zeek/etc/zeekctl.cfg
grep -n '^LogExpireInterval' /opt/zeek/etc/zeekctl.cfg
sudo /opt/zeek/bin/zeekctl deploy
(sudo crontab -l 2>/dev/null | grep -v 'zeekctl cron'; echo '*/5 * * * * /opt/zeek/bin/zeekctl cron') | sudo crontab -
sudo crontab -l

# Suricata: the package ships /etc/logrotate.d/suricata; make sure the timer runs
sudo systemctl enable --now logrotate.timer
systemctl is-active cron logrotate.timer
sudo logrotate -d /etc/logrotate.d/suricata 2>&1 | grep -c error     # expect 0
```

**Test 3.8 (pass/fail).** `LogExpireInterval = 14` appears once; the root crontab has exactly one `zeekctl cron` line; `cron` and `logrotate.timer` are both `active`; the dry run reports 0 errors; Zeek is `running`.

> **Disk size gotcha.** The Ubuntu installer's default LVM layout may use only part of the disk (this lab's 40 GB sensor disk showed a 19 GB root volume). If space gets tight, first check that free space exists (`sudo vgs`), then: `sudo lvextend -r -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv`.

### 3.9 Ship logs to Elastic

1. In Fleet, create the `network-sensor` policy and add both integrations:
   - **Zeek** — base path `/opt/zeek/logs/current` (the default fits this sensor). It requires the JSON logs enabled in 3.7.
   - **Suricata** — log file path `/var/log/suricata/eve.json` (the default).
2. Enroll the Elastic Agent on the sensor: Fleet → Agents → Add agent → `network-sensor` policy → Linux tar. Run the download commands Fleet shows, then:

   ```bash
   sudo ./elastic-agent install \
     --url=https://10.10.10.176:8220 \
     --enrollment-token=<network-sensor-token> \
     --insecure
   ```

   Same `--insecure` reasoning as the other hosts — see the [Fleet TLS note](#a-note-on-fleet-tls-and---insecure). The agent installs as root, so it can read both log directories.

**Test 3.9 (pass/fail).** `sudo elastic-agent status` shows `HEALTHY`, and Fleet shows the agent **Healthy** under `network-sensor`. After a few minutes, in Kibana Discover (time range: last 15 minutes):

```
data_stream.dataset : "zeek.connection"
data_stream.dataset : "suricata.eve" and suricata.eve.event_type : "alert"
rule.name : "CSN TEST ICMP echo request"
```

- **Pass:** all three return recent events. Ping `10.10.10.1` from the victim once and the `rule.name` count rises by exactly 4, with `source.ip` `10.10.10.186` and `destination.ip` `10.10.10.1`.

> `event.type : "alert"` does **not** work for Suricata: in this integration `event.type` holds values such as `allowed` or `protocol`. The alert marker is `suricata.eve.event_type`.
> Expect a lot of Zeek and Suricata rows for the victim's own Elastic Agent traffic to `10.10.10.176:9200` and `:8220`. That is normal, since the victim's tap is mirrored. Exclude it when writing detections.

### 3.10 Verify with a scan, then snapshot

Take a "before" reading in the sensor:

```bash
sudo /opt/zeek/bin/zeekctl netstats
sudo grep 'capture.kernel_packets' /var/log/suricata/stats.log | tail -1
date -u +%H:%M:%S
```

From Kali (VM 101; check its IP with `ip -br a`), scan the Win11 victim:

```bash
sudo nmap -Pn -sS --top-ports 100 10.10.10.186
```

Wait about 20 seconds (Suricata writes stats every 8 seconds), take the same three readings again, then in Kibana run:

```
data_stream.dataset : "zeek.connection" and source.ip : "<kali-ip>" and destination.ip : "10.10.10.186"
```

**Test 3.10 (pass/fail).**
- **Zeek saw the scan:** the Kibana query returns roughly 90+ events (nmap probes 100 ports).
- **Zeek lost nothing:** `netstats` still shows `dropped=0` and `recvd` rose.
- **Suricata saw the volume:** `capture.kernel_packets` rose by at least 200 between readings.
- **Record, not pass/fail:** whether Suricata alerts on the scan (`data_stream.dataset : "suricata.eve" and source.ip : "<kali-ip>"`, then look at `rule.name`). Whether ET rules fire on a plain SYN scan tells you what a Suricata-based detection can and cannot do.

> `capture.kernel_drops` may not appear in `stats.log` at all. Treat Suricata's drop count as unconfirmed unless it prints, and use Zeek's `dropped=0` as the loss indicator.

When everything passes, take the snapshot: `sensor-clean-<date>`. After reverting the sensor (or a victim) to a snapshot, restart the VM and re-run the 3.4 checks, since the mirror rules live on the Proxmox host, not in the snapshot.

### 3.11 Troubleshooting notes

| Symptom | Cause / fix |
| --- | --- |
| Capture shows nothing on the guest NIC | Mirror rules missing after a VM restart — re-run `/var/lib/vz/snippets/csn-mirror.sh 0 post-start`; check the hookscript is attached to **both** the victim and the sensor. |
| Suricata `active` but no alerts | `suricata -T` and `suricata.log` — a duplicate or bad rule makes signature loading fail while the service stays up. Check that `local.rules` is listed once. |
| `Duplicate signature ... sid` | `local.rules` registered twice in `rule-files:`. Use the guarded command in 3.6, or delete the extra line. |
| `crontab: command not found` | Install `cron` (3.8). Without the `zeekctl cron` job, `LogExpireInterval` never runs. |
| Suricata logs never rotate | `logrotate` not installed or `logrotate.timer` not enabled (3.8). |
| `zeekctl netstats` warns about websockets | `sudo apt install -y python3-websockets`. |
| Zeek data streams empty in Kibana | Logs are still tab-separated — confirm `@load policy/tuning/json-logs.zeek` is in `local.zeek`, then `zeekctl deploy` and check that `conn.log` starts with `{`. |
| Attacker traffic missing from Suricata alerts | `EXTERNAL_NET` still `!$HOME_NET` (3.6, step 3). |
| Wrong interface captured | Interface names differ from this lab's `ens19`/`ens20`. Match by MAC (3.5). |

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

- [ ] Lab bridge confirmed isolated (no route to home LAN; outbound internet via OPNsense is fine)
- [ ] Fleet policies created: `linux-victim`, `domain-controller`, `network-sensor`
- [ ] **Linux victim** built, auditd + Agent healthy, ART installed, snapshot taken
- [ ] **Domain controller** promoted (`csn.lab`), seeded, Win11 joined, audit policy on, snapshots taken (DC + re-snapshot Win11)
- [ ] **Network sensor**: `vmbr2` capture bridge, `tc` mirror of victim taps + hookscript (survives victim and sensor restarts), capture NIC service, Suricata (test rule alerts exactly 4×), Zeek (JSON logs, boot service), log retention, `network-sensor` agent healthy, scan test passed, snapshot taken
- [ ] **C2 server** running Caldera, agent checks in from Win11, snapshot taken

Once these are green, the Tier 2 and Tier 3 exercises in the roadmap all have the infrastructure they need.
