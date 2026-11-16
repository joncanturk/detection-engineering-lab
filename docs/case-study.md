# Synthetic investigation: one workstation timeline

This is a constructed demonstration, not a customer incident or an emulation run. Records are normalized examples, not collected Windows events. IP 192.0.2.10 is documentation space. The encoded string represents a harmless output command; the evaluator only inspects text and never executes it.

| UTC time, 2026-01-01 | Observation | Rule |
|---|---|---|
| 00:00:00–00:02:40 | Five failures for LAB/analyst from 192.0.2.10 on LAB-WS01 | DE001 |
| 00:03:20 | PowerShell process command line includes -enc | DE002 |
| 00:04:00 | A local account is created | DE004 |
| 00:04:40 | A SID is added to Administrators | DE005 |
| 00:05:20 | Security log clear event | DE003 |
| 00:06:40 | Successful logon example | No direct rule match |

## Assessment

The temporal proximity and shared host justify investigation. They do not prove that failed logons caused compromise or that one actor performed all subsequent actions. The account-creation fixture lacks a target SID, so it cannot establish that the created account is the member later added to Administrators. Record this as an evidence gap rather than assuming the connection.

## Next evidence

Obtain original events, actor and target SIDs, logon IDs, parent-process telemetry, authorized change records and available EDR/PowerShell history. Resolve the source IP and review successful logons. Check whether forwarding continued after the log-clear event. Correlate identities before attributing the sequence to one actor.

## Reproduce

Run `python -m lab.engine data/demo.jsonl`. It returns five alerts with references to the original synthetic records. Review the linked rule triage documents and record authorized/suspicious/insufficient-evidence dispositions. This offline tool performs no containment or account changes.
