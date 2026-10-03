# Lab NN: <Technique name> (<ATT&CK ID>)

Analyst: · Date (local / UTC): · Tier: · Victim host:

## 1. Result

One to three sentences, written last, placed first.

- **Technique executed on victim:** Yes / No (proof: see Evidence 1)
- **Detected on first run:** Yes / No (by existing rule, by hunting, or not at all)
- **Detection rule written:** Yes / No (name)
- **Fired on re-run:** Yes / No (alert timestamp)
- **Verdict:** Detection trusted / Needs tuning / Gap remains

## 2. Objective and ATT&CK mapping

One sentence on what this exercise teaches.

| Tactic | Technique | Sub-technique | Observed evidence supporting the mapping |
| --- | --- | --- | --- |

Map only what you observed, not what the atomic could theoretically do.

## 3. Environment (only what changed since the last lab)

Hosts involved, IPs, telemetry sources enabled (Sysmon, PowerShell logging, auditd, Zeek).

## 4. Hypothesis (written BEFORE running the test)

- Expected telemetry: which data source, which event IDs, which fields
- Expected process chain
- What would prove me wrong

## 5. Emulation

| Time (local / UTC) | Phase (prep / attack / cleanup) | Command | Purpose |
| --- | --- | --- | --- |

## 6. Evidence

1. **Execution confirmed on victim:** the event(s) proving it ran.
2. **Process chain:** one row per hop.

| Time (UTC) | process.name | process.entity_id | process.parent.name | process.parent.entity_id | process.command_line |
| --- | --- | --- | --- | --- | --- |

3. **Query that returns it:** index pattern + KQL/EQL.
4. **Hypothesis check:** what matched, what didn't, and why.

## 7. Detection rule

- Name, type, index pattern, severity, ATT&CK mapping on the rule
- Query (code block)
- Which clause matches which hop in the chain
- Source: written from scratch, or adapted from a prebuilt rule (credit it, list changes)

## 8. Test cases

| # | Case | Expected | Actual | Pass |
| --- | --- | --- | --- | --- |
| 1 | Re-run of the atomic | Alert fires | | |
| 2 | Benign look-alike (e.g. legitimate remoting) | Behavior documented | | |
| 3 | Near miss (e.g. similar parent, different args) | No alert | | |

## 9. False positives and gaps

- Legitimate activity that matches, and how to exclude it
- Variants of the technique this rule would miss

## 10. Next steps

Tracker row updated: Y/N. One concrete follow-up.
