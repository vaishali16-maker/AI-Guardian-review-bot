import asyncio
import hashlib
import hmac
import json
import logging
import os
from collections import OrderedDict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from diff_utils import build_diff
from github_api import fetch_pr_diff, post_pr_comment
from review_ai import get_ai_review

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
MAX_DIFF_CHARS = 30000
FAILURE_COMMENT = "Guardian could not complete this review"
SEEN_DELIVERIES = OrderedDict()
MAX_SEEN_DELIVERIES = 1000
latest_jobs = {}
job_sequence = 0


def verify_signature(body: bytes, signature_header) -> bool:
    """Check that the request really came from GitHub."""
    if not WEBHOOK_SECRET or not signature_header:
        return False
    expected = "sha256=" + hmac.new( WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _append_file_footer(review_text, skipped_files, truncated_files):
    lines = []
    if skipped_files:
        lines.append("Skipped files: " + ", ".join(skipped_files))
    if truncated_files:
        lines.append("Truncated files: " + ", ".join(truncated_files))
    return review_text + ("\n\n" + "\n".join(lines) if lines else "")


async def process_review(owner, repo, pr_number, installation_id, delivery_id=None):
    logger.info("Starting review repo=%s/%s pr=%s delivery=%s", owner, repo, pr_number, delivery_id)
    try:
        files = await asyncio.to_thread(fetch_pr_diff, owner, repo, pr_number, installation_id)
        diff_text, skipped_files, truncated_files = build_diff(files, MAX_DIFF_CHARS)
        review_text = await asyncio.to_thread(get_ai_review, diff_text)
        review_text = _append_file_footer(review_text, skipped_files, truncated_files)
        await asyncio.to_thread(post_pr_comment, owner, repo, pr_number, review_text, installation_id)
        logger.info("Review posted repo=%s/%s pr=%s delivery=%s file_count=%s", owner, repo, pr_number, delivery_id, len(files))
    except Exception as exc:
        logger.error("Review failed repo=%s/%s pr=%s delivery=%s exception_type=%s", owner, repo, pr_number, delivery_id, type(exc).__name__)
        try:
            await asyncio.to_thread(post_pr_comment, owner, repo, pr_number, FAILURE_COMMENT, installation_id)
        except Exception as comment_exc:
            logger.error("Failure comment failed repo=%s/%s pr=%s exception_type=%s", owner, repo, pr_number, type(comment_exc).__name__)


async def worker(queue):
    while True:
        owner, repo, pr_number, installation_id, delivery_id, version = await queue.get()
        try:
            key = (owner, repo, pr_number)
            if latest_jobs.get(key) == version:
                await process_review(owner, repo, pr_number, installation_id, delivery_id)
            else:
                logger.info("Skipped stale review repo=%s/%s pr=%s delivery=%s", owner, repo, pr_number, delivery_id)
        finally:
            queue.task_done()


@asynccontextmanager
async def lifespan(app):
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET is empty; webhook requests will be rejected")
    app.state.review_queue = asyncio.Queue()
    task = asyncio.create_task(worker(app.state.review_queue))
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan)


@app.post("/webhook")
async def github_webhook(request: Request):
    body = await request.body()
    if not verify_signature(body, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(status_code=401, detail="Invalid signature")

    delivery_id = request.headers.get("X-GitHub-Delivery")
    if delivery_id and delivery_id in SEEN_DELIVERIES:
        logger.info("Ignored duplicate delivery=%s", delivery_id)
        return {"status": "received"}
    if delivery_id:
        SEEN_DELIVERIES[delivery_id] = None
        SEEN_DELIVERIES.move_to_end(delivery_id)
        while len(SEEN_DELIVERIES) > MAX_SEEN_DELIVERIES:
            SEEN_DELIVERIES.popitem(last=False)

    payload = json.loads(body)
    event_type = request.headers.get("X-GitHub-Event")
    action = payload.get("action")
    if event_type == "pull_request" and action in ("opened", "synchronize", "reopened", "ready_for_review"):
        if payload.get("sender", {}).get("type") == "Bot" or payload.get("pull_request", {}).get("draft", False):
            logger.info("Ignored pull request event delivery=%s", delivery_id)
            return {"status": "received"}
        owner = payload["repository"]["owner"]["login"]
        repo = payload["repository"]["name"]
        pr_number = payload["pull_request"]["number"]
        installation_id = payload["installation"]["id"]
        key = (owner, repo, pr_number)
        global job_sequence
        job_sequence += 1
        latest_jobs[key] = job_sequence
        queue = request.app.state.review_queue
        await queue.put((owner, repo, pr_number, installation_id, delivery_id, job_sequence))
        logger.info("Queued review repo=%s/%s pr=%s delivery=%s", owner, repo, pr_number, delivery_id)
    return {"status": "received"}


@app.get("/")
async def root():
    return {"message": "Guardian Review Bot is running"}
