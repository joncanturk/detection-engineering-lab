# Validation report

Validated locally on Windows with Python 3.13.5 on 2026-11-16.

## Reproduction

```sh
python -m unittest discover -s tests -v
python -m lab.engine data/demo.jsonl
```

The suite contains 10 test methods, including the 32 named scenarios below as subtests. The demo is checked against the committed five-alert golden output. Additional checks exercise input validation, exact evidence references, timezone offsets, out-of-order input, channel/provider isolation, event identity and CLI errors. The GitHub Actions matrix is configured but has not run remotely.

## Scenario inventory

| Scenario | Expected rules |
|---|---|
| DE001 five failures inside window | DE001 |
| DE001 four failures below threshold | No alert |
| DE001 inclusive boundary | DE001 |
| DE001 outside boundary | No alert |
| DE001 sustained burst deduplicates | DE001 |
| DE001 rearm after quiet period | DE001, DE001 |
| DE001 separate host | No alert |
| DE001 separate target_user | No alert |
| DE001 separate target_domain | No alert |
| DE001 separate source_ip | No alert |
| DE001 missing target_user | No alert |
| DE001 missing target_domain | No alert |
| DE001 missing source_ip | No alert |
| DE002 encoded switch | DE002 |
| DE002 mixed case pwsh | DE002 |
| DE002 plain command | No alert |
| DE002 unrelated executable | No alert |
| DE002 switch prefix is not a match | No alert |
| DE002 missing command line | No alert |
| DE003 security log clear | DE003 |
| DE003 wrong provider | No alert |
| DE003 other channel | No alert |
| DE004 local account | DE004 |
| DE004 domain account | No alert |
| DE004 unknown scope | No alert |
| DE005 administrators SID | DE005 |
| DE005 localized name irrelevant | DE005 |
| DE005 ordinary users group | No alert |
| DE005 missing SID | No alert |
| benign approved admin change still alerts | DE005 |
| benign approved account creation still alerts | DE004 |
| benign logon success | No alert |

## Interpretation

Approved local account creation and administrator-group changes intentionally alert. These examples demonstrate that a correct rule match can still describe benign activity. Synthetic labels do not measure production precision, recall or false-positive rate. Encoded-command switches are indicators, not proof of malicious PowerShell execution.

## Mapping revision

DE003 now reports T1685.005 after review of the current MITRE ATT&CK page. The corresponding ATT&CK value in the golden output was changed explicitly; event selection, evidence IDs, timestamps and alert count remain unchanged.
