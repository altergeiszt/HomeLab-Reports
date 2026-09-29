# Project CSN — Purple Team Roadmap

Sep 28, 2026 · @Aaron Bagay

## Purpose and the practice loop

This roadmap turns Project CSN into a repeatable purple-team workshop: emulate a known adversary technique, see whether the lab detects it, capture the evidence, then close the gap. Each exercise runs the same four-step loop, and the loop matters more than any single exercise.

1. **Attack** — run one mapped technique (an Atomic Red Team test, a C2 action, a hand-run command) against a victim host from the attacker box.
2. **Detect** — hunt for it in Elastic. Does an existing rule fire? If not, can you find the activity by searching the raw telemetry (Sysmon, auditd, Zeek)?
3. **Capture** — record what the technique looked like in the data: the exact events, fields, and timestamps that prove it happened. This is your detection evidence.
4. **Refine** — write or tune a detection rule so the next run fires cleanly, then note the gap you closed and any false positives.

The blue-team goal is a detection you trust; the red-team goal is understanding why the technique works and how it shows up. You play both sides, which is the point of purple teaming. Every technique maps to a MITRE ATT&CK ID, so coverage is tracked against a real framework rather than a personal checklist.

Run one technique per session, to a written detection, before moving on. A half-detected technique left open is the pattern that stalls this kind of work — finish the loop, log it, then pick the next.

## What counts as done, and what to record

An exercise is done when all four are true:

- [ ] The technique ran and you confirmed it executed on the victim (not just that the tool reported success).
- [ ] You found the activity in Elastic — either a rule fired, or you located it in raw telemetry.
- [ ] You captured the specific evidence: index, the fields that identify the technique, and a query that returns it.
- [ ] A detection rule exists that fires on a re-run, with false positives noted.

Keep one record per exercise in the companion tracker. Each record holds the same fields: the ATT&CK technique ID and name, the tier, the victim host, how you ran it, whether it was detected on the first run, the data source and query that caught it, the detection rule you wrote, and any notes on false positives or gaps. The next section covers the tracker; the fields there match this list so nothing gets eyeballed.

## Lab build-out order and resource budget

The 32 GB / 16-thread Proxmox node is the constraint that shapes the whole roadmap. Elastic is the heavy tenant, so it gets a fixed allocation and everything else fits around it. You add VMs tier by tier rather than all at once, and you shut down what a given exercise doesn't need.

A workable steady-state budget on the node:

| VM | Role | vCPU | RAM | Runs during |
| --- | --- | --- | --- | --- |
| Elastic (SIEM + Fleet) | Detection stack | 4 | 8–10 GB | Always |
| Windows 11 victim | Endpoint w/ Sysmon + Agent | 2–4 | 4–6 GB | Always |
| Kali attacker | Red-team box | 2 | 2–4 GB | Always |
| Linux victim | Endpoint w/ auditd + Agent | 2 | 2 GB | Tier 2+ |
| Windows Server DC | AD domain controller | 2 | 4 GB | Tier 2+ (AD) |
| Zeek/Suricata sensor | Network detection | 2 | 2–4 GB | Tier 2+ |
| C2 server | Caldera / Sliver | 2 | 2 GB | Tier 3+ |

All seven at once overcommits 32 GB, which is why exercises are scoped: an AD lateral-movement exercise runs Elastic + DC + two Windows hosts + Kali and leaves the C2 and network sensor off unless that exercise needs them. OPNsense already handles the lab network on the firewall mini PC, so the Zeek/Suricata sensor taps a mirrored port or bridge rather than living inline. Proxmox Backup Server on the mini PC snapshots each known-good VM state so you can revert a victim after a destructive test.

One network note that pays off early: put victims, attacker, and the DC on an isolated lab VLAN with no route to your home LAN, and only Elastic reachable for management. It keeps emulation traffic contained and makes the telemetry clean.

## Tier 0 — Foundations (current state)

This tier is your baseline: the emulate-then-detect stack running end to end on one technique, proving the loop works before you scale it. You have already done this.

- **Done — TCP port scan (T1046, Network Service Discovery).** You ran a scan from the attacker box against the Windows victim and confirmed the emulate-then-detect stack sees it. That is the loop closed once: attack fired, telemetry captured, detection confirmed. Treat this as exercise 0 in the tracker and backfill its record so the format is set before Tier 1.

Before leaving Tier 0, confirm the foundation is solid enough to build on:

- [ ] Elastic Fleet is managing the Windows Agent and pulling Sysmon + Windows event logs reliably.
- [ ] Atomic Red Team is installed and you can invoke a test on demand.
- [ ] You can write a basic Elastic detection rule and see it fire.
- [ ] PBS has a clean snapshot of the victim to revert to.

With those green, the loop is trustworthy and every later tier is just more technique coverage on the same machinery.

## Tier 1 — Beginner: single-technique Windows endpoint

Goal: build detection fluency on the host you already have. Every exercise here is one Atomic Red Team test against the Windows victim, run to a working detection. No new infrastructure — you are learning to read Sysmon and write Elastic rules. Aim to clear most of these before moving on; they are the vocabulary for everything above.

Suggested order, easy to harder within the tier:

| # | Technique | ATT&CK | What you learn to detect |
| --- | --- | --- | --- |
| 1 | Command & scripting: PowerShell | T1059.001 | Suspicious PowerShell process + command line |
| 2 | Windows Command Shell | T1059.003 | cmd.exe spawning, parent-child chains |
| 3 | Scheduled task creation | T1053.005 | schtasks / Task Scheduler event 4698 |
| 4 | Registry Run key persistence | T1547.001 | Run-key writes via Sysmon event 13 |
| 5 | Local account creation | T1136.001 | net user, event 4720 |
| 6 | Masquerading (rename binary) | T1036.003 | Process name vs. original filename mismatch |
| 7 | Credential dump: LSASS access | T1003.001 | Sysmon event 10, handle to lsass.exe |
| 8 | Defense evasion: clear event logs | T1070.001 | event 1102, wevtutil |

For each: fire the Atomic, hunt in Elastic, capture the identifying fields, then write the rule. The LSASS and clear-logs exercises are the ones worth lingering on — they are high-signal detections that map directly to real intrusions, and getting a clean rule with few false positives is a genuine skill.

Exit criterion: you can take an unfamiliar Atomic, predict which Sysmon events it will generate, and write a detection without looking up the answer first.

## Tier 2 — Intermediate: Linux, network, and Active Directory

Goal: expand the attack surface and the telemetry sources. You add three things here — a Linux victim, a network sensor, and an AD domain — and each opens a family of techniques the single Windows host could not show. Build them in that order; AD is the biggest jump and benefits from having network detection already in place.

**2a — Linux victim (auditd + Elastic Agent).** Stand up a Linux endpoint, ship auditd and Agent telemetry to Elastic, then run the Linux Atomics.

| Technique | ATT&CK | Detection focus |
| --- | --- | --- |
| Bash/shell execution & reverse shell | T1059.004 | Process + network from a shell |
| Cron persistence | T1053.003 | crontab writes, new cron processes |
| SSH authorized\_keys persistence | T1098.004 | file writes to authorized\_keys |
| Account/system discovery | T1087 / T1082 | recon command bursts |

**2b — Network detection (Zeek/Suricata sensor).** Bring up the sensor on a mirrored port from OPNsense. Now re-run techniques you already detected on the host and watch them from the network angle — this is where purple teaming gets interesting, because you see the same attack in two data sources.

| Technique | ATT&CK | Detection focus |
| --- | --- | --- |
| Port/service scan (re-run of T1046) | T1046 | Zeek conn logs, scan patterns |
| C2 over HTTP/DNS (preview of Tier 3) | T1071 | beaconing, odd JA3/DNS |
| Data exfil over the network | T1048 | large/odd outbound flows |

**2c — Active Directory domain.** Stand up a Windows Server DC, join the Windows victim, add a second workstation if RAM allows. This unlocks the credential-and-lateral-movement techniques that define real intrusions.

| Technique | ATT&CK | Detection focus |
| --- | --- | --- |
| Kerberoasting | T1558.003 | event 4769, unusual service ticket requests |
| Pass-the-hash | T1550.002 | anomalous NTLM logons, event 4624 type 3 |
| Remote service exec (PsExec-style) | T1021.002 | event 7045, service creation + lateral logon |
| DCSync | T1003.006 | replication requests from a non-DC |

Exit criterion: you can detect a technique in more than one data source, and you have at least one AD credential-access detection you trust. That combination is the core of an intrusion-detection skill set.

## Tier 3 — Advanced: C2 and chained emulation

Goal: stop running isolated techniques and start running intrusions. You add a command-and-control framework and chain techniques into a realistic kill chain, then detect the whole sequence rather than one event at a time. This is where the individual detections from Tiers 1–2 have to work together.

**3a — Stand up a C2 framework.** Caldera is the natural fit here — it is MITRE's own adversary-emulation platform, it maps operations to ATT&CK for you, and it can chain abilities into an operation automatically. Sliver is the alternative if you want a more realistic implant and hands-on operator experience; Mythic if you want to go deeper still. Start with Caldera for the ATT&CK mapping, add Sliver later for realism.

First C2 exercises, detecting the implant itself:

| Technique | ATT&CK | Detection focus |
| --- | --- | --- |
| Agent beaconing / C2 channel | T1071 | periodic callbacks, Zeek + host |
| Process injection | T1055 | Sysmon event 8/10, injected threads |
| Encrypted/encoded channel | T1573 / T1132 | odd entropy, encoding on the wire |

**3b — Chained adversary emulation.** Run a multi-stage operation and detect it as a story. A good first chain, mirroring a real intrusion:

1. Initial execution on the Windows victim (phishing-style payload).
2. Discovery — enumerate the host and the domain.
3. Credential access — dump credentials or Kerberoast.
4. Lateral movement — pivot to a second host or the DC.
5. Collection & exfiltration — stage data and move it out.

Detect each stage, then step back: can you reconstruct the full timeline in Elastic from first execution to exfil? Can you link the stages to one operation? That reconstruction — turning scattered alerts into one incident — is the advanced blue-team skill this tier builds. Emulate a named threat actor's TTPs (Caldera ships adversary profiles) so the chain matches something real.

Exit criterion: you can run an unscripted multi-stage operation and produce an incident timeline that a reviewer could follow, with detections firing at more than one stage.

## Tier 4 — Capstone and the exercise tracker

**Capstone.** Once Tier 3 is comfortable, the capstone is a full purple-team engagement you run against yourself: pick a threat actor, plan an intrusion from initial access to objective, execute it end to end, and produce a report as if handing it to a defender — what you did, what fired, what was missed, and the detections you added to close the gaps. Run it, improve your detections, then run it again and measure the difference. That before/after is the clearest proof the lab is teaching you something.

Good capstone extensions when you want them: add a purpose-built detection-gap review (run the whole ATT&CK Navigator layer of what you have covered vs. not), or time yourself from first alert to full incident reconstruction and try to bring it down.

**The tracker.** The companion sheet is where every exercise lives as a row — one line per technique, with its ATT&CK ID, tier, whether it was detected first-run, the data source and query that caught it, the rule you wrote, and false-positive notes. It is the visible progress tracker for this whole roadmap: filter by tier to see where you are, filter by "not detected first-run" to see your gap list. The fields match the record definition in the second section, so status is tracked, not eyeballed.

I'll build that tracker next as a separate piece so you can review this roadmap first.
