# Guardian Review AI

A GitHub App that reviews pull requests for security vulnerabilities and posts structured, severity-ranked findings as a single, continuously updated comment.

**Live bot:** https://ai-guardian-review-bot.onrender.com (free tier; the first request after idle can take ~50 seconds)

> Screenshot: PR comment with findings — add `docs/pr-comment.png` here.

## What it does

When a pull request is opened or updated, Guardian:

1. Verifies the webhook signature (HMAC-SHA256).
2. Fetches the PR diff (paginated, up to 300 files; lockfiles and generated files skipped).
3. Sends the diff to an LLM (Groq, `openai/gpt-oss-120b`) as untrusted data.
4. Validates the model's JSON output, renders it into markdown in code, and posts it as **one bot comment that is edited in place** on every push.

## Architecture
GitHub webhook ──► FastAPI /webhook ──► verify HMAC ──► dedupe / filter
│
async queue + worker
│
fetch PR files ◄── GitHub App auth (JWT → installation token)
│
build_diff (skip lockfiles, per-file caps)
│
LLM review (system prompt, random boundary, temperature 0)
│
validate JSON findings ──► render_review (escaped markdown)
│
create/update bot comment


## Security design

- **Webhook authentication:** HMAC-SHA256 on the raw request body with constant-time comparison; missing or invalid signatures return 401 before any processing.
- **Replay and noise control:** deduplication by `X-GitHub-Delivery`, bot senders and draft PRs ignored, stale queued jobs skipped when a newer push arrives.
- **Prompt-injection mitigation:** instructions live in the system message; the diff goes in the user message inside a per-request random boundary token; the token is stripped from the diff; instruction-like phrases in the diff add a visible finding. This reduces risk and is not a guarantee.
- **Safe rendering:** the model never writes the final comment. Findings are validated, escaped, and rendered by code; @mentions and autolinks are defanged; fix code goes in dynamically sized fenced blocks.
- **Comment hijack protection:** the bot only updates comments that carry its marker **and** were written by a bot account.
- **No sensitive logging:** diff contents, tokens, and response bodies are never logged.
- **Resilience:** timeouts everywhere, retries with backoff on 429/5xx, `Retry-After` capped at 30 seconds, and a visible failure comment instead of silent errors.

## Evaluation

I built a small benchmark to measure the reviewer instead of guessing: **25 vulnerable and 15 safe look-alike Python snippets** across 12 vulnerability categories, 3 runs per case, temperature 0. Labels and keyword lists were frozen before any results were produced (SHA-256 recorded in each results file).

| Prompt | Recall (vulnerable runs) | False-positive rate (safe runs) | Run-level precision | Consistency |
|---|---:|---:|---:|---:|
| **v1 (production)**, run 1 | 100% (75/75) | 28.9% (13/45) | 85.2% | 92.5% |
| **v1 (production)**, rerun | 100% (75/75) | 22.2% | 88.2% | 87.5% |
| v2 (conservative, experiment) | 70.7% (53/75) | 8.9% (4/45) | 93.0% | 82.5% |

**What I learned**

- A stricter prompt cut false positives by roughly two thirds but lost about a third of true detections. It missed `shell=True` command injection in all 6 runs and several SQL injection, XSS and SSRF cases whose input arrived through a plain function parameter.
- Identical prompt and cases produced a 28.9% and a 22.2% false-positive rate on two runs, so single-run numbers are fragile.
- **I deploy v1.** For a security tool, a missed vulnerability costs more than an extra warning, so the bot reports speculative findings with severity and confidence for human triage. The v2 prompt is kept as `benchmark/prompts/v2_conservative.txt` with its hash tested.
- The benchmark exposed two real bugs in my validator (valid findings dropped when optional metadata was missing); both were fixed.

**Limits:** the benchmark is small, self-written, textbook-style, and covers one model. Recall figures describe detection on these snippets, not general accuracy, and fix quality is not measured. The three runs per case are not independent samples. A free-text baseline was attempted but keyword scoring on prose was unreliable, so it is not reported.

Reproduce: `python benchmark/run_benchmark.py --prompt hardened --tag my_run` (about 17 minutes; uses API quota).

## Setup

1. Create a GitHub App with webhook URL `https://<your-host>/webhook`, a webhook secret, and permissions for Pull requests (read) and Issues (write); subscribe to Pull request events.
2. Set environment variables: `APP_ID`, `PRIVATE_KEY`, `WEBHOOK_SECRET`, `GROQ_API_KEY`.
3. `pip install -r requirements.txt` then `uvicorn main:app --host 0.0.0.0 --port 10000`.
4. Tests: `pip install -r requirements-dev.txt` then `pytest -v` (74 tests, mocked network calls).

CI runs the test suite on every pull request; the default branch requires an approving review.

## Limitations and future work

- The queue and dedupe state are in memory, so a restart loses pending jobs (next step: Redis or Celery).
- The reviewer sees only the diff, so it can state wrong claims about code it cannot see.
- LLM output varies between runs; confidence labels are not calibrated.
- Single model, single language (Python), no static-analysis hybrid yet (Bandit/Semgrep would be the next addition).