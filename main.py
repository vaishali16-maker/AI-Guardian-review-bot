#import statements
from fastapi import FastAPI, Request
from github_api import fetch_pr_diff, post_pr_comment
from review_ai import get_ai_review
import asyncio

app = FastAPI()
review_queue = asyncio.Queue()


async def process_review(owner, repo, pr_number):
    print(f"PR #{pr_number} in {owner}/{repo} — starting review...")
    try:
        files = fetch_pr_diff(owner, repo, pr_number)
        diff_text = ""
        for file in files:
            filename = file.get("filename")
            patch = file.get("patch", "No diff available")
            diff_text += f"File: {filename}\n{patch}\n\n"
        review_text = get_ai_review(diff_text)
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
    payload = await request.json()
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
