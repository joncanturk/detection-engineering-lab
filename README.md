# Detection Engineering Lab

Five explainable Windows detections with synthetic telemetry, repeatable tests and analyst triage guides.

Built for a security portfolio: follow each hypothesis from its source event through the matching logic, evidence and investigation. Everything runs offline with the Python standard library. No real accounts, agents or cloud services are required.

**Release:** 0.1.0 · **Status:** experimental lab · **Data:** synthetic only

## Quick start

Requires Python 3.11 or newer. From the repository directory, on Windows, Linux or macOS:

```sh
python -m unittest discover -s tests -v
python -m lab.engine data/demo.jsonl
python -m lab.engine data/demo.jsonl --output alerts.json
```

Use `python3` if that is your Python command. No dependency installation is needed.
The demo produces **five alerts**, one per rule. Compare the complete output with [expected-alerts.json](examples/expected-alerts.json).

## MITRE ATT&CK coverage

The project follows [MITRE ATT&CK Enterprise](https://attack.mitre.org/). See the [mapping rationale and coverage boundaries](docs/attack-coverage.md). Technique mappings were reviewed on 2026-11-16.

| Rule | Behavior | Telemetry | ATT&CK | Guide |
|---|---|---|---|---|
| DE001 | At least 5 failed logons / 5 minutes for one host, domain, user and IP | 4625 | T1110.001 | [Triage](docs/triage/DE001.md) |
| DE002 | PowerShell with `-enc` or `-encodedcommand` | 4688 + command line | T1059.001 | [Triage](docs/triage/DE002.md) |
| DE003 | Security audit log cleared | 1102 | T1685.005 | [Triage](docs/triage/DE003.md) |
| DE004 | Local user account created | 4720 + scope enrichment | T1136.001 | [Triage](docs/triage/DE004.md) |
| DE005 | Member added to built-in Administrators | 4732 + group SID | T1098.007 | [Triage](docs/triage/DE005.md) |

An alert is an investigation lead, not a verdict. Account creation and group changes can be entirely legitimate. ATT&CK mappings express possible behavior, not attribution.

## How it works

```text
Normalized JSONL -> validate identity/time -> chronological evaluation
                -> exact/regex/rolling-window rules -> JSON alerts + evidence IDs
```

Rules are declarative JSON in a small **lab-specific format**, not Sigma, SPL or KQL. The evaluator executes these same files; there is no separate hard-coded copy of detection conditions. See [schema and rule semantics](docs/schema.md).

## Portfolio evidence

- [Validation report](docs/validation.md): named scenarios, boundaries and limitations.
- [Synthetic investigation](docs/case-study.md): what the demo supports and what it cannot prove.
- [Five triage guides](docs/triage/DE001.md): hypotheses, false positives, tuning and blind spots.
- [CI workflow](.github/workflows/tests.yml): tests on Windows and Linux, Python 3.11 and 3.13.

## Repository map

```text
rules/                 Executable detection definitions
lab/engine.py          Offline evaluator and CLI
data/demo.jsonl        One synthetic demonstration timeline
data/scenarios.json    Named positive, negative and boundary fixtures
tests/                 Scenario, input validation and CLI tests
examples/              Expected demo output
docs/                  Field mapping, validation, investigation and triage
```

## Deployment boundaries

This is an educational reference evaluator, not a production SIEM integration. It reads normalized JSONL, not EVTX or native XML. It loads and sorts the entire input in memory, does not retain state between runs and does not perform automated response. Real deployments need a collector/normalizer, performance testing, persistent correlation state, alert routing, telemetry-quality monitoring and environment-specific tuning. The included fixtures cannot establish production precision or recall.

Only the two documented encoded-command switch forms are detected. Account scope must be enriched reliably. Duplicate event identities are rejected; callers must partition archive segments when Windows record numbers are reused after a clear. Do not ingest production secrets or customer logs into this public repository.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and the [MIT license](LICENSE). Proposed behavioral changes should include both triggering and non-triggering examples.

## Telemetry implementation references

MITRE ATT&CK is the behavioral framework. The references below document Windows event fields and collection requirements.

- [Microsoft: 4625 failed logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft: 4688 process creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft: audit configuration and event IDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft: events to monitor, including 1102](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor)
- MITRE ATT&CK references are linked in each rule's triage guide.
