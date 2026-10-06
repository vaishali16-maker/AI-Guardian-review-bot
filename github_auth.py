import logging
import os
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import jwt
import requests
from dotenv import load_dotenv

load_dotenv()
APP_ID = os.getenv("APP_ID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
logger = logging.getLogger(__name__)
RETRY_STATUSES = {429, 502, 503, 504}


def generate_jwt():
    if not PRIVATE_KEY or not APP_ID:
        raise RuntimeError("GitHub App credentials are not configured")
    private_key = PRIVATE_KEY.replace("\\n", "\n")
    now = int(time.time())
    payload = {'iat': now, 'exp': now + (10 * 60), 'iss': APP_ID}
    return jwt.encode(payload, private_key, algorithm='RS256')


def get_installation_token(installation_id):
    token = generate_jwt()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    url = f'https://api.github.com/app/installations/{installation_id}/access_tokens'
    response = None
    for attempt in range(3):
        response = requests.post(url, headers=headers, timeout=30)
        logger.info("GitHub token API status=%s", response.status_code)
        if response.status_code in RETRY_STATUSES:
            if attempt < 2:
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = min(30, float(retry_after)) if retry_after else 2 ** attempt
                except ValueError:
                    try:
                        retry_time = parsedate_to_datetime(retry_after)
                        if retry_time.tzinfo is None:
                            retry_time = retry_time.replace(tzinfo=timezone.utc)
                        delay = min(30, max(0, (retry_time - datetime.now(timezone.utc)).total_seconds()))
                    except (TypeError, ValueError, OverflowError):
                        delay = 2 ** attempt
                time.sleep(max(0, delay))
                continue
            break
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not data.get("token"):
            raise ValueError("GitHub token response did not contain a token")
        return data["token"]
    raise requests.HTTPError(
        f"GitHub token request failed after 3 attempts (status {response.status_code})",
        response=response,
    )
