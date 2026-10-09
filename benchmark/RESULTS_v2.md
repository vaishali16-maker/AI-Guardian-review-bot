# Guardian Review AI benchmark results

Prompt mode: **hardened**
SYSTEM_PROMPT SHA-256: `33030b826d90a800f9582b00ee4d3fee6b7e93a0badb336f75735cee7238eadd`
Date: 2026-10-09

Cases SHA-256: `cf984816fd04ad60bc8d15c06cc21913d4cd63008f0d0f64f5edb6d9df677fc0`

Labels frozen before results

**Scoring differs by mode, and naive and hardened numbers are not directly comparable.** Hardened mode scores structured findings by accepted CWE or category keywords and counts safe-case findings at medium severity or higher. Naive mode scores vulnerable cases by category keywords in free text and safe cases by any named vulnerability after removing plain no-issue claims.

Runs per case: **3**. Cases: **40**.

Metrics are aggregated over individual runs except consistency, which is the fraction of cases whose three binary outcomes all agree.

| Metric | Result |
|---|---:|
| Overall recall | 70.7% |
| Safe-case false-positive rate | 8.9% |
| Precision | 93.0% |
| Three-run consistency | 82.5% |
| Parse errors | 1 |
| Dropped findings | 0 |

## Recall by vulnerable category

| Category | Detected runs | Missed runs | Recall |
|---|---:|---:|---:|
| code_execution | 5 | 1 | 83.3% |
| command_injection | 0 | 6 | 0.0% |
| debug_mode_enabled | 3 | 0 | 100.0% |
| hardcoded_secret | 9 | 0 | 100.0% |
| insecure_deserialization | 6 | 0 | 100.0% |
| insecure_randomness | 6 | 0 | 100.0% |
| path_traversal | 4 | 2 | 66.7% |
| sql_injection | 5 | 4 | 55.6% |
| ssrf | 3 | 3 | 50.0% |
| tls_verification_disabled | 1 | 2 | 33.3% |
| weak_crypto | 6 | 0 | 100.0% |
| xss | 5 | 4 | 55.6% |
