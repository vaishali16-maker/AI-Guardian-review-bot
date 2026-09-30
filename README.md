# Guardian Review AI 🤖🔒

An AI-powered GitHub bot that automatically reviews Pull Requests for **security vulnerabilities**, explaining findings in **plain, beginner-friendly language**. It's built for solo developers and small teams who don't have a dedicated security reviewer on hand.

**Live bot:** `https://ai-guardian-review-bot.onrender.com`

---

## What it does

The moment a developer opens or updates a Pull Request, Guardian Review AI:

1. Detects the event instantly via a GitHub webhook
2. Verifies the webhook signature to confirm the request really came from GitHub
3. Authenticates as a GitHub App (JWT → installation token)
4. Fetches the code diff via GitHub's REST API
5. Sends the diff (capped at a safe size) to an LLM (Groq) with a security-focused review prompt
6. Posts the AI's findings back as a comment on the PR, automatically, with no human needing to trigger it
7. Generates unit tests for the changed code, giving contributors a starting point for test coverage

It specifically checks for:

- Hardcoded secrets (API keys, passwords, tokens)
- SQL injection / command injection risks
- Unsafe functions (`eval()`, `exec()`, etc.)
- Missing input validation and other common vulnerability patterns

---

## Why security-specific, not general code review?

Most AI PR bots already handle generic style and bug checking. Very few focus specifically on **security**, and even fewer explain findings in language a beginner can actually act on instead of jargon-heavy alerts. This makes the bot useful for solo developers and small teams without a dedicated security reviewer.

---

### Unit Test Generation

Alongside the security review, Guardian Review AI generates unit tests for the changed code in each PR, giving contributors test coverage to start from even if they didn't write tests themselves. Useful for solo devs and small teams under time pressure.

---

## Architecture

```
Developer opens/updates PR
        │
        ▼
GitHub Webhook  ──►  FastAPI /webhook endpoint
        │
        ▼
Verify HMAC signature (X-Hub-Signature-256)  ──►  reject with 401 if invalid
        │
        ▼
Async Queue  ──►  Background worker (processes one PR at a time)
        │
        ▼
GitHub App Auth (JWT → Installation Token)
        │
        ▼
Fetch PR diff (GitHub REST API)  ──►  truncate if over size limit
        │
        ▼
AI Security Review (Groq — openai/gpt-oss-120b)
        │
        ▼
Post review as PR comment (GitHub REST API)
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| Auth | GitHub App (PyJWT + `cryptography` for RS256 signing) |
| Webhook security | HMAC-SHA256 signature verification |
| AI | Groq API (`openai/gpt-oss-120b`) |
| Concurrency | `asyncio.Queue` + background worker |
| Testing | `pytest` + `unittest.mock` |
| CI | GitHub Actions |
| Deployment | Render |

---

## Security measures

- **Webhook signature verification:** every incoming request is checked against GitHub's `X-Hub-Signature-256` header using a shared secret (`WEBHOOK_SECRET`). The raw request body is verified *before* any JSON parsing, and the comparison uses `hmac.compare_digest` to prevent timing attacks. Requests with a missing or invalid signature are rejected with `401`, so nobody can trigger reviews (and burn API quota) by sending fake events to the public URL.
- **No secrets in code:** all credentials (GitHub App key, Groq key, webhook secret) are read from environment variables.
- **Diff size limit:** the diff sent to the model is capped at 30,000 characters. If a PR exceeds this, the review covers the first part and the bot adds a visible warning to the comment, so a partial review is never presented as a complete one.

---

## Reliability & scale considerations

- **Concurrency:** incoming webhook events are placed on an async queue and processed one at a time by a background worker, so overlapping PR events never race against each other or the GitHub/Groq APIs simultaneously.
- **Rate limiting:** API calls check GitHub's remaining rate-limit headers and log a warning when running low; both GitHub and Groq calls retry automatically with exponential backoff on `429` responses.
- **Testing:** core logic (webhook filtering, signature verification, diff parsing, AI response parsing, retry behavior) is covered by unit tests using mocked API responses, so no real network calls are needed to verify correctness.
- **At larger scale** (thousands of repos), the next step would be replacing the in-memory queue with a persistent task queue (e.g. Celery + Redis) so work survives restarts and can be distributed across multiple workers.

---

### Notes on reliability

During testing, a transient Groq API key issue caused reviews to silently fail (the response lacked the expected structure). This was resolved by improving error logging to surface the full API response rather than just the missing key. It was a good reminder that error messages should always show what actually happened, not just what didn't.

---

## Repository safety net (demonstrated on this repo)

This repo itself uses the same safeguards a real team would rely on:

- **CI (GitHub Actions):** every PR automatically runs the test suite before it can be considered mergeable.
- **Branch protection:** merging into `main` requires at least one approving review, so the PR author cannot self-merge.
- **CODEOWNERS:** changes to Python files specifically require approval from a designated code owner, not just anyone with write access.

The AI review is advisory. It informs, but a human still makes the final merge decision, the same way real production review tools (and real teams) operate.

---

## Local development

```bash
git clone https://github.com/vaishali16-maker/AI-Guardian-review-bot.git
cd AI-Guardian-review-bot
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

Create a `.env` file with:

```
APP_ID=your_github_app_id
INSTALLATION_ID=your_installation_id
PRIVATE_KEY_PATH=path/to/your/private-key.pem
GROQ_API_KEY=your_groq_api_key
WEBHOOK_SECRET=your_webhook_secret
```

Generate a webhook secret with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the **same value** in your GitHub App's webhook secret field (GitHub App settings → Webhook → Secret) and in your deployment environment variables. If `WEBHOOK_SECRET` is not set, all webhooks are rejected.

Run locally:

```bash
uvicorn main:app --reload --port 8000
```

Expose it to the internet for GitHub webhooks during local testing:

```bash
ngrok http 8000
```

---

## Running tests

```bash
pytest test_main.py -v
```

---

## Project structure

```
.
├── main.py              # FastAPI app, webhook handler, signature check, async queue/worker
├── github_auth.py       # GitHub App authentication (JWT + installation token)
├── github_api.py        # Fetch PR diffs, post PR comments, retry logic
├── review_ai.py         # Groq API call + security review prompt
├── test_main.py         # Unit tests (mocked API calls)
├── requirements.txt
└── .github/
    ├── workflows/tests.yml   # CI pipeline
    └── CODEOWNERS
```

---

## Possible future improvements

- Replace the in-memory queue with a persistent queue (Celery + Redis)
- Read the installation ID from each webhook payload so the bot can be installed by multiple accounts
- Add prompt-injection mitigations for untrusted diff content
- Combine with a static analysis tool (e.g. Semgrep) and have the LLM explain its findings

---

## Status

Deployed and actively tested end-to-end: webhook delivery, signature verification, authentication, diff fetching, AI review generation, and comment posting have all been verified against real GitHub Pull Requests, including PRs containing intentionally planted vulnerabilities (SQL injection, hardcoded secrets, unsafe `eval()` usage) to confirm the bot correctly identifies real issues rather than defaulting to "no issues found."
