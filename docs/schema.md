# Event contract and rule semantics

## Input

UTF-8 JSON Lines: one object per nonblank line. A UTF-8 BOM is accepted. Core fields below are validated before evaluation. Optional detection fields may be absent; their rule then fails to match. A missing field must never be interpreted as proof of benign behavior.

| Normalized field | Type / origin |
|---|---|
| `record_id` | Nonempty string from EventRecordID; unique per host/channel within a batch |
| `timestamp` | ISO 8601 string with explicit timezone from System.TimeCreated.SystemTime |
| `host` | Nonempty canonical host string from System.Computer |
| `channel` | Nonempty string from System.Channel; these rules require `Security` |
| `provider` | Nonempty string from System.Provider.Name |
| `event_id` | Integer from System.EventID |
| `target_user`, `target_domain` | 4625 TargetUserName and TargetDomainName; normalize casing consistently upstream |
| `source_ip` | 4625 IpAddress; normalize equivalent IP representations upstream |
| `process_path` | 4688 NewProcessName |
| `command_line` | 4688 CommandLine; requires command-line auditing |
| `account_scope` | Trusted enrichment: `local`, `domain` or `unknown`; NOT a native 4720 field |
| `group_sid` | 4732 TargetSid; built-in Administrators is S-1-5-32-544 |
| `member_sid` | 4732 MemberSid, retained for investigation |
| `actor` | Optional normalized subject identity for investigation |

4720 alone does not distinguish local from domain account creation in this model. Use asset role and original domain/SID evidence during normalization. Do not blindly label domain-controller events as local. Channel/provider checks prevent unrelated events with coincidentally identical IDs from matching. Event 1102 uses Microsoft-Windows-Eventlog, while the other four use Microsoft-Windows-Security-Auditing.

Enable and verify Audit Logon failures, Audit Process Creation (plus Include command line in process creation events), Audit User Account Management and Audit Security Group Management where needed. Validate against actual forwarded records; this repository does not configure these policies.

## Rules

`rules/*.json` are trusted project configuration, not arbitrary untrusted input. Each has an ID, title, status, severity, ATT&CK list and `equals` object. All exact predicates AND together with every `required` and `regex` predicate. Exact values are case-sensitive; regex case-insensitivity is explicit. Python regular expressions are used. Do not load untrusted regex rules.

DE001 uses `threshold`: count, seconds and grouping fields. Events are sorted by absolute time. The window includes both endpoints: age <= 300 seconds. It emits when a group transitions from below five to at least five observations, suppresses further alerts while the window remains above threshold and rearms once it falls below threshold. A sixth event is not appended to a previously emitted alert's evidence. Grouping keeps hosts, domains, users and source IPs separate. No state survives a CLI invocation. Split batches may miss bursts across their boundaries.

The evaluator's public CLI validates data through `load_events`; direct Python callers should do the same. Duplicates are rejected rather than counted. Sorting makes out-of-order batch input reproducible but is not a streaming late-arrival policy. Unknown extra fields are retained in input and ignored unless a rule references them.

## Output

A JSON array with rule ID, title, severity, ATT&CK list, triggering timestamp, host and composite evidence references. Exit code 0 means evaluation succeeded (including when alerts exist); 2 means invalid input, configuration or file access. Empty input produces `[]`. The tool never executes log content or issues network requests.
