# Guardian Review AI benchmark

Run from the repository root after configuring the same API environment used by the app:

```bash
python benchmark/run_benchmark.py
python benchmark/run_benchmark.py --limit 5 --prompt hardened
python benchmark/run_benchmark.py --limit 5 --prompt naive
```

The runner uses the configured Groq model, makes three requests per case, and waits two seconds between requests for a case. It writes aggregate Markdown metrics to `benchmark/RESULTS.md` and per-run outputs, decisions, and errors to `benchmark/results.json`. `--limit N` selects the first N dataset entries. `--prompt hardened` uses `review_ai.get_ai_review`; `--prompt naive` sends the original plain-text prompt directly from the runner without JSON instructions or diff delimiters.

## Scoring

For hardened mode, a vulnerable case is detected when a finding has an accepted CWE or a category keyword appears in its title or explanation. A safe case is a false positive if any finding has medium-or-higher severity. For naive mode, vulnerable detection uses category keywords in free text; a safe case is a false positive if vulnerability terms appear outside a plain no-issues claim. The results document states this scoring difference. Recall, false-positive rate, and precision aggregate the three binary decisions per case. Consistency is the fraction of cases for which all three decisions agree. Parse errors are counted per run.

All snippets are fictional, small, self-written educational examples. They are not intended for deployment. Tests load the dataset and exercise pure scoring helpers; they do not make API requests.

## Limits

This is a small, self-written benchmark evaluated with a single model. It does not establish real-world security coverage, and results vary run to run. Keyword matching can miss paraphrases or reward superficial mentions. The safe examples cannot represent every context, and the labeled cases require human review before drawing strong conclusions.
