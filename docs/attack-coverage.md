# MITRE ATT&CK coverage

Framework: [MITRE ATT&CK Enterprise](https://attack.mitre.org/). Mapping review date: **2026-11-16**. This is an independent educational project, not a MITRE-endorsed product.

## Technique mappings

| Rule | Official technique | Tactic | What this lab observes |
|---|---|---|---|
| DE001 | [T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Credential Access | Repeated failed logons for one host, account and source |
| DE002 | [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Execution | PowerShell process creation with two encoded-command switch forms |
| DE003 | [T1685.005: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) | Defense Impairment | Security-channel log-clear event 1102 |
| DE004 | [T1136.001: Local Account](https://attack.mitre.org/techniques/T1136/001/) | Persistence | Account creation enriched as local |
| DE005 | [T1098.007: Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/) | Persistence, Privilege Escalation | Addition to the built-in Administrators group |

## Mapping rationale and limits

- **DE001:** A failed-logon burst is consistent with guessing, but stale credentials can create the same pattern. Five failures in five minutes is a lab design choice, not a MITRE-prescribed threshold. It does not demonstrate successful access or cover password spraying.
- **DE002:** Process and command-line evidence support a narrow PowerShell analytic. The technique also includes execution paths and behaviors this rule cannot observe. Encoding alone does not establish malicious intent.
- **DE003:** The current technique ID is T1685.005. The earlier T1685.005 mapping was replaced during this review. Event 1102 observes a clear action; this lab does not implement the full elevation-and-clearing behavioral chain described by MITRE's linked detection strategy.
- **DE004:** Local account creation can support persistence, but a matching event does not establish that the account is adversary-controlled. Scope enrichment is required; unknown scope is not silently treated as local.
- **DE005:** Membership changes can expand privileges. This implementation covers only the built-in Administrators SID, not every local/domain group described by the technique.

## Coverage claims

All five mappings represent **partial behavioral visibility**. No coverage percentage or detection efficacy score is claimed. Rule metadata records the canonical technique URL, name, tactics and review date. The alert output retains technique IDs for downstream linking. Detection strategy and analytic IDs are not claimed as implemented unless their complete logic is separately tested.

## Maintenance

Review canonical MITRE pages when updating rules. If a technique is renamed, revoked or replaced, update rule metadata, README, triage references and expected alert output together. Document the reason for any golden-output change. Use Windows vendor documentation for event schemas and audit-policy details; ATT&CK provides the behavior taxonomy.
