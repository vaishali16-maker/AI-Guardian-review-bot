# Guardian Review AI benchmark results

Cases SHA-256: `cf984816fd04ad60bc8d15c06cc21913d4cd63008f0d0f64f5edb6d9df677fc0`

Labels frozen before results

**Scoring differs by mode, and naive and hardened numbers are not directly comparable.** Hardened mode scores structured findings by accepted CWE or category keywords and counts safe-case findings at medium severity or higher. Naive mode scores vulnerable cases by category keywords in free text and safe cases by any named vulnerability after removing plain no-issue claims.

Prompt mode: **hardened**. Runs per case: **3**. Cases: **40**.

Metrics are aggregated over individual runs except consistency, which is the fraction of cases whose three binary outcomes all agree.

| Metric | Result |
|---|---:|
| Overall recall | 100.0% |
| Safe-case false-positive rate | 28.9% |
| Precision | 85.2% |
| Three-run consistency | 92.5% |
| Parse errors | 0 |
| Dropped findings | 0 |

## Recall by vulnerable category

| Category | Detected runs | Missed runs | Recall |
|---|---:|---:|---:|
| code_execution | 6 | 0 | 100.0% |
| command_injection | 6 | 0 | 100.0% |
| debug_mode_enabled | 3 | 0 | 100.0% |
| hardcoded_secret | 9 | 0 | 100.0% |
| insecure_deserialization | 6 | 0 | 100.0% |
| insecure_randomness | 6 | 0 | 100.0% |
| path_traversal | 6 | 0 | 100.0% |
| sql_injection | 9 | 0 | 100.0% |
| ssrf | 6 | 0 | 100.0% |
| tls_verification_disabled | 3 | 0 | 100.0% |
| weak_crypto | 6 | 0 | 100.0% |
| xss | 9 | 0 | 100.0% |
