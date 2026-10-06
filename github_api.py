import logging
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests
from github_auth import get_installation_token

logger = logging.getLogger(__name__)
RETRY_STATUSES = {429, 502, 503, 504}
TIMEOUT = 30
COMMENT_MARKER = "<!-- guardian-review-bot -->"


def _retry_delay(response, attempt):
    value = response.headers.get("Retry-After")
    if value:
        try:
            return min(30, max(0, float(value)))
        except ValueError:
            try:
                retry_time = parsedate_to_datetime(value)
                if retry_time.tzinfo is None:
                    retry_time = retry_time.replace(tzinfo=timezone.utc)
                return min(30, max(0, (retry_time - datetime.now(timezone.utc)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                pass
    return 2 ** attempt


def make_request_with_retry(method, url, headers, json_body=None, max_retries=3):
    response = None
    for attempt in range(max_retries):
        started = time.monotonic()
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=json_body, timeout=TIMEOUT)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=json_body, timeout=TIMEOUT)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        logger.info("GitHub API status=%s elapsed=%.2fs", response.status_code, time.monotonic() - started)
        if response.status_code in RETRY_STATUSES:
            if attempt + 1 == max_retries:
                break
            time.sleep(_retry_delay(response, attempt))
            continue
        response.raise_for_status()
        return response
    status = response.status_code if response is not None else "no response"
    raise requests.HTTPError(f"GitHub request failed after {max_retries} attempts (status {status})", response=response)


def fetch_pr_diff(owner, repo, pr_number, installation_id):
    token = get_installation_token(installation_id)
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'}
    base_url = f'https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files'
    files = []
    response = None
    for page in range(1, 4):
        response = make_request_with_retry("GET", f"{base_url}?per_page=100&page={page}", headers)
        page_files = response.json()
        if not isinstance(page_files, list):
            raise ValueError("GitHub PR files response must be a list")
        files.extend(page_files[:300 - len(files)])
        if len(page_files) < 100 or len(files) >= 300:
            break
    logger.info("Fetched PR files repo=%s/%s pr=%s file_count=%s status=%s", owner, repo, pr_number, len(files), response.status_code)
    return files


def find_bot_comment(owner, repo, pr_number, installation_id):
    token = get_installation_token(installation_id)
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'}
    base_url = f'https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments'
    for page in range(1, 1001):
        comments = make_request_with_retry("GET", f"{base_url}?per_page=100&page={page}", headers).json()
        if not isinstance(comments, list):
            raise ValueError("GitHub comments response must be a list")
        match = next((
            item for item in comments
            if COMMENT_MARKER in item.get("body", "")
            and (
                (item.get("user") or {}).get("type") == "Bot"
                or (item.get("user") or {}).get("login", "").endswith("[bot]")
            )
        ), None)
        if match:
            return match
        if len(comments) < 100:
            return None
    raise RuntimeError("GitHub comment search exceeded the pagination limit")


def update_pr_comment(owner, repo, comment_id, comment_text, installation_id):
    token = get_installation_token(installation_id)
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'}
    url = f'https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}'
    response = make_request_with_retry("PATCH", url, headers, {"body": f"{COMMENT_MARKER}\n{comment_text}"})
    logger.info("Updated PR comment repo=%s/%s status=%s", owner, repo, response.status_code)
    return response.json()


def post_pr_comment(owner, repo, pr_number, comment_text, installation_id):
    existing = find_bot_comment(owner, repo, pr_number, installation_id)
    if existing:
        return update_pr_comment(owner, repo, existing["id"], comment_text, installation_id)
    token = get_installation_token(installation_id)
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json'}
    url = f'https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments'
    body = {'body': f"{COMMENT_MARKER}\n{comment_text}"}
    response = make_request_with_retry("POST", url, headers, json_body=body)
    logger.info("Created PR comment repo=%s/%s pr=%s status=%s", owner, repo, pr_number, response.status_code)
    return response.json()
