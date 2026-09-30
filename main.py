#import statements
import hashlib
import hmac
import json
import os

from fastapi import FastAPI, Request, HTTPException
from github_api import fetch_pr_diff, post_pr_comment
from review_ai import get_ai_review
import asyncio

app = FastAPI()
review_queue = asyncio.Queue()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
MAX_DIFF_CHARS = 30000  # about 7-8k tokens; adjust if needed


def verify_signature(body: bytes, signature_header) -> bool:
    """Check that the request really came from GitHub."""
    if not WEBHOOK_SECRET or not signature_header:
        return False
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


async def process_review(owner, repo, pr_number):
    print(f"PR #{pr_number} in {owner}/{repo} — starting review...")
    try:
        files = fetch_pr_diff(owner, repo, pr_number)
        diff_text = ""
        was_truncated = False
        for file in files:
            filename = file.get("filename")
            patch = file.get("patch", "No diff available")
            chunk = f"File: {filename}\n{patch}\n\n"
            if len(diff_text) + len(chunk) > MAX_DIFF_CHARS:
                remaining = MAX_DIFF_CHARS - len(diff_text)
                diff_text += chunk[:max(remaining, 0)]
                was_truncated = True
                break
            diff_text += chunk

        review_text = get_ai_review(diff_text)

        if was_truncated:
            review_text += (
                "\n\n> ⚠️ This PR was too large to review fully. "
                "Only the first part of the diff was analyzed."
            )

        post_pr_comment(owner, repo, pr_number, review_text)
        print("✅ Review posted successfully")
    except Exception as e:
        print(f"❌ Error during review: {e}")


async def worker():
    while True:
        owner, repo, pr_number = await review_queue.get()
        await process_review(owner, repo, pr_number)
        review_queue.task_done()


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(worker())


@app.post("/webhook")
async def github_webhook(request: Request):
    body = await request.body()
    if not verify_signature(body, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = json.loads(body)
    event_type = request.headers.get("X-GitHub-Event")
    action = payload.get("action")
    print(f"\n🔔 Received event: {event_type}")
    print(f"Action: {action}")

    if event_type == "pull_request" and action in ("opened", "synchronize"):
        owner = payload["repository"]["owner"]["login"]
        repo = payload["repository"]["name"]
        pr_number = payload["pull_request"]["number"]
        await review_queue.put((owner, repo, pr_number))
        print(f"📥 Queued PR #{pr_number} for review (queue size: {review_queue.qsize()})")
    return {"status": "received"}


@app.get("/")
async def root():
    return {"message": "Guardian Review Bot is running"}