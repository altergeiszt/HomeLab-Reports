# Lab 01 Documentation

September 27, 2026

Aaron Bagay

## Objective and ATT&CK mapping

This is an exercise on detection rules, detection policy improvement and event logging.

The chosen MITRE ATT&CK tactics and techniques stated in the table below builds a solid a foundation for understanding how attackers can bypass detection rules, and how defenders can improve it.

| Tactic | Technique | Sub-technique | Applies when |
| --- | --- | --- | --- |
| Discovery (TA0007) | Network Service Discovery (T1046) | -- | Scanner is inside the network |
| Reconnaissance (TA0043) | Active Scanning (T1595) | Scanning IP Blocks (T1595.001) | Scanner is external, pre-compromise |

## Lab Environment

All Virtual Machines used in this lab are on an isolated network behing OPNSense, hosted on a Proxmox Machine. The table below lists each machine, their roles, local IP and key software that were used.

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

## Telemetry

Steps taken for scan visibility and expected output:

- Audit policy enabled: auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable and "Filtering Platform Packet Drop" /failure:enable
  - We chose to go failure-only since success auditing will log every allowed connection.

- Events: 5152 (packet dropped) and 5157 (connection blocked), from the Windows Security lg via the Elastic System Integration.

- Key fields: source.ip = scanner, destination port = probed port, direction = inbound.

- Volume: [324] documents for 100-port scan. We got this from nmap retrying unanswered probes, and Windows logging both 5152 and 5157 events for the same packet.

- We had a late-packet noise from 10.10.10.176:9200, and we hypothesize that the elastic-siem, win11-victim and Kali vms are not properly synchronized in the clock which caused the discrepancy of results.

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
| 1 | Preview | Rule preview, last 1 hour | One hit for 10.10.10.190 only | Pass | Pass |
| 2 | True Positive | Top-100 port scan | Alert within ~6 minutes, ran @ 15:57 | Pass, alerts created within time frame | Pass |
| 3 | Below Threshold | Scan of 3 ports | No alert | 1 Alert Created | Fail |
| 4 | Quiet Baseline | 15 min idle | No alert | No alerts | Pass |
| 5 | Evasion | --scan-delay 30s | Unknown | No Alerts | No baseline |

## Findings and Gaps

- Finding 1 : Slow scan 

- Finding 2 : Endpoint-only visibility
  - Only the Windows virtual machine can log the events, other hosts in the Proxmox VE environment are blind. Fix: Implement network-level telemetry in next session.

- Finding 3 : Workflow confusion
  - Discover and Alerts are separate functionalities. Discover just reports the scan has been seen, Alerts reports when rules are triggered.

## Lessons Learned

| Symptom | Root Cause |
| --- | --- |
| Scan events missing from Kibana's recent time ranges | Windows VM time zone were wrong. so UTC timestamp were 2 hours behind. |
| whoami and Kali events are missing from local queries | -MaxEvents returned only the newest events, which were background noise. |
| Free-text IP search in Kibana returned nothing | IPs live in typed fields that free-text search does not cover. |

## For Next Session

- [ ] Forward OPNSense firewall logs (and optionally Suricata) to Elastic for network level scan-detection.
- [ ] Build and test a rule that can catch a slow scan.
- [ ] Rewrite the rule in Sigma for portability.
- [ ] Read Elastic/Kibana documentation for proper usage.
  