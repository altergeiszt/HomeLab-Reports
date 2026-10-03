# Project CSN: Exercise Tracker

One row per technique. Fields follow the roadmap's record definition. Full evidence, queries and rule logic live in each lab report, so this table points to it rather than repeating it.

**Status key:** Done (loop closed and logged) · In progress · Not started
**Detected first run:** Yes / No / n/a (not run yet). "No" means no rule fired and the activity was found by hunting.

**Progress:** Tier 0: 1/1 · Tier 1: 1/8 · Tier 2: 0/11 · Tier 3: 0/4 · Capstone: not started

## Tracker

| # | Tier | ATT&CK | Technique | Victim | Status | Detected first run | Data source | Detection rule | Report / notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | T1046 | Network Service Discovery (TCP port scan) | Windows victim | Done | No | Sysmon event 5152, 5154 | TODO | `Port Scan Detection (T1046 and T1595.001).md` |
| 1 | 1 | T1059.001 | PowerShell (Atomic Test 13, via SSH session) | win11-victim | Done | No | Sysmon event 1 | CSN - Powershell remote execution (SSH/WinRM), rev 3 | `Lab02 - T1059.001 Test 13 report.md`. Rule matches any PowerShell child in a remoting session. 4103/4104 not observed. WinRM branch, look-alike and near-miss untested |
| 2 | 1 | T1059.003 | Windows Command Shell | win11-victim | Not started | n/a | | | |
| 3 | 1 | T1053.005 | Scheduled Task creation | win11-victim | Not started | n/a | | | |
| 4 | 1 | T1547.001 | Registry Run key persistence | win11-victim | Not started | n/a | | | |
| 5 | 1 | T1136.001 | Local account creation | win11-victim | Not started | n/a | | | |
| 6 | 1 | T1036.003 | Masquerading (rename binary) | win11-victim | Not started | n/a | | | |
| 7 | 1 | T1003.001 | Credential dump: LSASS access | win11-victim | Not started | n/a | | | |
| 8 | 1 | T1070.001 | Clear Windows event logs | win11-victim | Not started | n/a | | | |
| 2a-1 | 2 | T1059.004 | Bash/shell execution and reverse shell | Linux victim | Not started | n/a | | | |
| 2a-2 | 2 | T1053.003 | Cron persistence | Linux victim | Not started | n/a | | | |
| 2a-3 | 2 | T1098.004 | SSH authorized_keys persistence | Linux victim | Not started | n/a | | | |
| 2a-4 | 2 | T1087 / T1082 | Account and system discovery | Linux victim | Not started | n/a | | | |
| 2b-1 | 2 | T1046 | Port/service scan (re-run, network view) | Windows victim | Not started | n/a | | | |
| 2b-2 | 2 | T1071 | C2 over HTTP/DNS (preview) | | Not started | n/a | | | |
| 2b-3 | 2 | T1048 | Data exfil over the network | | Not started | n/a | | | |
| 2c-1 | 2 | T1558.003 | Kerberoasting | AD domain | Not started | n/a | | | |
| 2c-2 | 2 | T1550.002 | Pass-the-hash | AD domain | Not started | n/a | | | |
| 2c-3 | 2 | T1021.002 | Remote service exec (PsExec-style) | AD domain | Not started | n/a | | | |
| 2c-4 | 2 | T1003.006 | DCSync | AD domain | Not started | n/a | | | |
| 3a-1 | 3 | T1071 | Agent beaconing / C2 channel | | Not started | n/a | | | |
| 3a-2 | 3 | T1055 | Process injection | | Not started | n/a | | | |
| 3a-3 | 3 | T1573 / T1132 | Encrypted/encoded channel | | Not started | n/a | | | |
| 3b | 3 | chain | Chained adversary emulation (5-stage operation) | | Not started | n/a | | | |
| 4 | 4 | n/a | Capstone: full purple-team engagement (run, improve, re-run) | | Not started | n/a | | | |

## Open gaps (from completed labs)

| Source | Gap | Next action |
| --- | --- | --- |
| Lab 02 (#1) | No PowerShell 4103/4104 events seen for the test; cause unknown | Check Kibana and Event Viewer on win11-victim around 20:38 |
| Lab 02 (#1) | Benign look-alike and near-miss test cases not run | Short follow-up lab (harmless `New-PSSession` command; local `pwsh.exe` without `-sshs`) |
| Lab 02 (#1) | WinRM branch of the rule never exercised | Test over WinRM when convenient |
| Exercise 0 (T1046) | Record not backfilled | Fill in the row above using the same fields as row 1 |
