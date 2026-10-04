# Lab 02 Documentation

October 2, 2026

Aaron Bagay

## Summary

We emulated an activity where PowerShell commands/scripts are executed remotely without executing the powershell.exe binary directly. In this event, we used AtomicRedTeam's T1059.001 Test-13 atomic test. And we traced the test starting from an Out-AthPowershellCommandLineParameter call, all the way to an sshd.exe call that came from the Kali-Linux attack VM. The child -> parent chain went as follows:

Out-AthPowershellCommandLindParameter call -> powershell.exe -> pwsh.exe -> cmd .exe -> sshd.exe

## Exercise Objective

The goal for the exercise is to practice tracing processes back to its parent process's entity id which was then used to trace its origin, going deeper down the invocation chain until we couldn't step into it deeper. 

## ATT&CK Mapping
| Tactic | Technique | SubTechnique | Applies When: |
| --- | --- | --- | --- |
| Execution (TA0002) | Command and Scripting Interpreter (T1059) | PowerShell (T1059.001) | PowerShell commands are invoked and spawns suspicious activity |
| Lateral Movement (TA0008) | Remote Services (T1021) | SSH (T1021.004) | Remote Process execution |
| Lateral Movement (TA0008) | Remote Services (T1021) | Windows Remote Management (T1021.0006) | Remote access control | 

## Lab Environment

All Virtual Machines used in this lab are on an isolated network behind OPNSense, hosted on a Proxmox Machine. The table below lists each machine, their roles, local IP and key software that were used.

| Host | Role | IP | Key Software |
| --- | --- | --- | --- |
| elastic-siem | SIEM + Fleet Server | 10.10.10.150 | Ubuntu 24.04, Elasticsearch/Kibana 9.5.4 |
| win11-victim | Target Endpoint | 10.10.10.186 | Windows 11 Enterprise (eval), Sysmon (sysmon-modular), Elastic Agent |
| Kali-Linux | Attacker | 10.10.10.190 | Invoke-AtomicTest |
| OPNSense | Lab firewall/router | 10.10.10.1 | Lab Isolation from Home LAN |

## Emulation
| Time (Local) | Command | Purpose |
| --- | --- | --- |
| 10:59 | $sess = New-PSSession -Hostname win11-victim -username alter | Establish remote control access | 
| 11:06 | Invoke-AtomicTest T1059.001 -TestNumbers 13 -Session $sess -ShowDetails | Prints a detailed test commands |
| 11:10 | Invoke-AtomicTest T1059.001 -TestNumbers 13 -Session $sess -CheckPrereqs | Prepares test harness |
| 11:12 | Invoke-AtomicTest T1059.001 -TestNumbers 13 -Session $sess -GetPrereqs | Obtains atomic test harnesses |
| 11:20 | Invoke-AtomicTest T1059.001 -TestNumbers 13 -Session $sess | Invokes atomic test |
| 14:32 | Invoke-AtomicTest T1059.001 -TestNumbers 13 -Session $sess -Cleanup | Reverts environment to pre-test state |

## Telemetry
Steps taken to establish detection rules and its expected output:
- Sysmon EventCode = 1: System logs for processes.
- Powershell EventCode = 4103, 4104, 4105, 4106 : Broad command execution logs.
  - Narrowed down to 4103 and 4104.
    - Further narrowed down to 4104 after basic queries.
- Query parameters:
  - event.code = ElasticSearch filter for log events.
  - process.name
  - process.command_line = variable system calls executed by the process.
  - process.entity_id = unique process identifier
  - process.parent.name
  - process.parent.entity_id = unique parent process identifier.

## Detection Hypothesis

1. The T1059.001 is a process creation and command execution event using Powershell.
2. EventCodes = 1, 4103, 4104, 4105, 4106. The range was broad because I couldn't find exact documentation for EventCodes before running the test. 
3. Process chain = powershell.exe -> cmd.exe 
4. EQL query needs refinement, still unknown if wsmprovhost.exe is in the event chain.

## Alert rules
| Setting | Value |
| --- | --- |
| Rule Name | Powershell remote execution |
| Rule Type | Event Correlation |
| Index pattern | logs-windows.sysmon_operational-* | 

Eql query :
```
process where host.os.type == "windows" and event.type == "start" and
  (
    process.parent.name : "wsmprovhost.exe" or
    (process.parent.name : "pwsh.exe" and process.parent.args : "-sshs")
  )
```

## Detection Logic
- Rule type : "Event Corelation"
    - Event corelation was used to detect sequences of actions that can indicate a security threat.
- Index pattern: "logs-windows.sysmon_operational-*
    - Picked because of process create events.
- Process.parent.name : *
    - Events are created by another event.

## Findings
1. The powershell.exe and pwsh.exe are two separate processes that can trigger each other.
2. Remote process execution are common in remote administrative tasks, and can be used as a point of entry for malicious actors if not hardened properly.
3. Each processes have a unique entity id.


### Process notes
20:38 UTC-6 
{process.name = "powershell.exe" ;

process.args : "powershell.exe", "&", "{Out-ATHPowerShellCommandLineParameter", "'-CommandLineSwitchType", Hyphen, "'-CommandParamVariation", C, "'-Execute", "'-ErrorAction", "Stop}" ; 

process.entity_id : "{3DB7E871-6A91-6AC0-1402-000000000B00}" ; 

process.parent.name : "pwsh.exe"

process.parent.args : "c:/progra~1/powershell/7/pwsh.exe", "'-sshs", "'-NoLogo" ; 

process.parent.entity_id : "{3DB7E871-6A22-6AC0-0502-000000000B00}"}

{
  process.name "pwsh.exe" ;

  process.parent.name : "cmd.exe" ;

  process.parent.args : "c:\windows\system32\cmd.exe", "/c", "c:/progra~1/powershell/7/pwsh.exe -sshs -NoLogo" ;

  process.parent.entity_id : "{3DB7E871-6A22-6AC0-0302-000000000B00}" ;
}

{
  process.name : "cmd.exe"

  process.parent.name : "sshd.exe" ;

  process.parent.args : "C:\WINDOWS\System32\OpenSSH\sshd.exe", "'-z"

  process.parent.entity_id : "{3DB7E871-6A22-6AC0-0202-000000000B00}";
}

{
  process.name : "sshd.exe"

  proecss.args : "C:\WINDOWS\System32\OpenSSH\sshd.exe", "'-z"

  process.entity_id : "{3DB7E871-6A22-6AC0-0202-000000000B00}"

  process.parent.args : "C:\WINDOWS\System32\OpenSSH\sshd.exe", "'-R"

  process.parent.entity_id : "{3DB7E871-6A1E-6AC0-0002-000000000B00}"
}

{
  process.name : "sshd.exe" ;
  
  process.args : "C:\WINDOWS\System32\OpenSSH\sshd.exe", "'-R"

  process.entity_id : "{3DB7E871-6A1E-6AC0-0002-000000000B00}"

  process.parent.args : "C:\WINDOWS\System32\OpenSSH\sshd.exe"

  process.parent.entity_id : "{3DB7E871-59C8-6AC0-4400-000000000B00}"
}