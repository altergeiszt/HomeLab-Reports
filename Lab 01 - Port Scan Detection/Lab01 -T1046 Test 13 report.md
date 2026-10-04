# Lab 01 Documentation

September 27, 2026

Aaron Bagay

## Summary

We worked on an introductory exercise on detection engineering. We emulated a TCP port against a Windows 11 host and built an Elastic Threshold rule that detected common scans within a 6-minute window (5 minute period + 1 minute look back). A slow scan with a 15s delay was not detected, showing a gap within our detection logic.

## Objective and ATT&CK mapping

This is an exercise on detection rules, detection policy improvement and event logging.

The chosen MITRE ATT&CK tactics and techniques stated in the table below builds a solid a foundation for understanding how attackers can bypass detection rules, and how defenders can improve it.

| Tactic | Technique | Sub-technique | Applies when |
| --- | --- | --- | --- |
| Discovery (TA0007) | Network Service Discovery (T1046) | -- | Scanner is inside the network |
| Reconnaissance (TA0043) | Active Scanning (T1595) | Scanning IP Blocks (T1595.001) | Scanner is external, pre-compromise |

## Lab Environment

All Virtual Machines used in this lab are on an isolated network behind OPNSense, hosted on a Proxmox Machine. The table below lists each machine, their roles, local IP and key software that were used.

| Host | Role | IP | Key Software |
| --- | --- | --- | --- |
| elastic-siem | SIEM + Fleet Server | 10.10.10.176 | Ubuntu 26.04, Elasticsearch/Kibana 9.5.4 |
| win11-victim | Target Endpoint | 10.10.10.186 | Windows 11 Enterprise (eval), Sysmon (sysmon-modular), Elastic Agent |
| Kali-Linux | Attacker | 10.10.10.190 | nmap 7.99 |
| OPNSense | Lab firewall/router | 10.10.10.1 | Lab Isolation from Home LAN |

## Emulation

| Time (local) | Command | Purpose |
| --- | --- | --- |
| 13:34 | sudo nmap -sn 10.10.10.0/24 | IP-block sweep |
| 13:38 | sudo nmap -Pn -sS --top-ports 100 10.10.10.186 | Port scan (true positive test) |
| 13:40 | sudo nmap -Pn -sS -p 22,80,443 10.10.10.186 | Below-threshold test |
| 13:41 | sudo nmap -Pn -sS --top-ports 100 --scan-delay 15s 10.10.10.186 | Evasion test (slow scan) |
| 15:57 | sudo nmap -Pn -sS --top-ports 100 10.10.10.186 | Port scan (true positive test) |
| 20:04 | sudo nmap -Pn -sS --top-ports 100 10.10.10.186 | Port scan (true positive test) |
| 20:30 | sudo nmap -Pn -sS --top-ports 100 10.10.10.186 | Post scan true positive |
| 21:00 | sudo nmap -Pn -sS -p 22,80,443 10.10.10.186 | Below-threshold test |

## Telemetry

Steps taken for scan visibility and expected output:

- Audit policy enabled: auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable and "Filtering Platform Packet Drop" /failure:enable
  - We chose to go failure-only since success auditing will log every allowed connection.

- Events: 5152 (packet dropped) and 5157 (connection blocked), from the Windows Security logs via the Elastic System Integration.

- Key fields: source.ip = scanner, destination.port = probed port, direction = inbound.

- Volume: 5152 = probe to a port with no listener (dropped silently). 5157 = probe to a port behind a firewall rule. Counts exceed port counts because nmap retries unanswered probes.

- I included a Lab01-result.json file that details the logs from a captured 5152 event.

## Detection Logic

| Setting | Value |
| --- | --- |
| Rule name | Inbound Port Scan Detected (WFP) |
| Rule Type | Threshold |
| Index pattern | logs-system.security-* |
| Group by | source.ip |
| Threshold | >= 20 events and >= 20 unique destination.port |
| Schedule | Every 5 minutes, 1 minute additional look-back |
| Severity | Medium |

### Why we built the detection rule this way

- Rule Type : "Threshold"
  - Stray packets are dropped constantly, but when a lot of stray packets came from one source using a threshold rule is a good way to filter the signal.

- Index pattern: "logs-system.security-*"
  - We used this to narrow down the scope of logs where 5152 and 5157 events occurs.

- Query: "event.code : ("5152" or "5157")
  - These are the traffic that are blocked by Windows. When an attacker probes a machine, most probes hit a firewalled ports, so blocked traffic are used for the detection rule.

- Exclusion: "not (source.ip : "10.10.10.176" and source.port: (9200 or 8220))
  - This excludes server only when the traffic comes from its Elastic ports. A broad exclusion like "(ignore 10.10.10.176)" would create a blindspot an attacker can use for cover.

- Unique destination.port >= 20
  - Counting distinct ports measures breadth, and breadth separates an actual network scan from ordinary connection failures. We chose to filter for 20 unique destination.port because normal traffic rarely hits more than a handful of distinct ports from one source in a few minutes.

- Event count >= 20
  - Redundancy, 20 unique destination ports can match 20 events.

- Schedule: every 5 minutes with a 1-minute look-back
  - It runs for 5 minutes and searches the last 6, with the look-back period overlapping results from the last run are not missed between runs. However, a slower scan can be missed, which is why we need another rule with a longer run, or delay.

- Severity: Medium
  - A scan is a warning sign, and worth the time to check.

- ATT&CK mapping
  - An analyst seeing T1046 immediately knows what kind of activity it is. And mapping the rules to the ATT&CK framework can tell us what techniques we do or do not cover.

## Validation

| # | Test | Action | Expected | Actual | Pass or Fail |
| --- | --- | --- | --- | --- | --- |
| 1 | Preview | Rule preview, last 1 hour | One hit for 10.10.10.190 only | One hit for 10.10.10.190 only | Pass |
| 2 (Original)| True Positive | Top-100 port scan | Alert within ~6 minutes | Alerts created within window, ran at 15:57 | Pass |
| 2(Re-run 1) | True positive | Top-100 port scan | Alert with ~6 minutes | Alert created within window, ran at 20:04 | Pass |
| 2 (Re-run 2) | True Positive | Top 100 port scan | Alert within ~6 minutes | Alert created within window, ran at 20:30 | Pass |
| 3 (Original) | Below Threshold | Scan of 3 ports | No alert | 1 Alert Created | Fail |
| 3 (Re-run 1) | Below Threshold | Scan of 3 ports | No Alert | No alert | Pass |
|3 (Re-run 2) | Below Threshold | Scan of 3 ports | No Alert| No alert | Pass |
| 4 | Quiet Baseline | 15 min idle | No alert | No Alerts | Pass |
| 5 | Evasion | --scan-delay 30s | Unknown | No Alerts | No baseline |

## Alerts

| Alert time | Likely source |
| --- | --- |
| 11:07 | First scan today |
| 13:42 | 13:38 port scan (plus overlapping 13:40 test) |
| 16:02 | Test 2 run at 15:57 |
| 20:07 | Test 2 re-run 1 at 20:04 |
| 20:32 | Test 2 re-run 2 at 20:30 |

## Findings and Gaps

- Finding 1 : Slow scan
  - Slow scans require a different detection rule.

- Finding 2 : Endpoint-only visibility
  - Only the Windows virtual machine can log the events, other hosts in the Proxmox VE environment are blind. Fix: Implement network-level telemetry in next session.

- Finding 4 : Invalid tests requires proper test isolation.
  - Test 3 was within the 6 minute window of test 2 and 5, it needs to be re-ran with at least a 10-minute gap.

## Hypothesis

- We had a late or duplicate packets from the Elastic Server arriving after Windows closed the agent's connection. Dropped by the stealth filter

- When I re-run test 3 again after a minimum of 10 minutes after test 2, I should get about 6 events over 3 ports since Windows logs both 5152 and 5157 events with the same packet.
  - Result 6 events for 5152, and 0 events for 5157. Revised results are in the Validation table.

## Lessons Learned

| Symptom | Root Cause |
| --- | --- |
| Scan events missing from Kibana's recent time ranges | Windows VM time zone were wrong. so UTC timestamp were 2 hours behind. |
| whoami and Kali events are missing from local queries | -MaxEvents returned only the newest events, which were background noise. |
| Free-text IP search in Kibana returned nothing | IPs live in typed fields that free-text search does not cover. |
| Original test 3 was written as a failure. | Tests 2, 3 and 4 overlapped within the 6-minute window. |
|Workflow confusion | Discover and Alerts are separate functionalities. Discover just reports the scan has been seen, Alerts reports when rules are triggered. |

## For Next Session

- [ ] Forward OPNSense firewall logs (and optionally Suricata) to Elastic for network level scan-detection.
- [ ] Build and test a rule that can catch a slow scan.
- [ ] Rewrite the rule in Sigma for portability.
- [ ] Read Elastic/Kibana documentation for proper usage.
  
