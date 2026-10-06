import logging
import os
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
logger = logging.getLogger(__name__)


def get_ai_review(diff_text):
    prompt = (
        "You are a security-focused code reviewer. Review this code diff for "
        "security vulnerabilities, hardcoded secrets, injection risks, and unsafe "
        "patterns. Explain issues in plain language for a beginner. If there are "
        "no issues, say so briefly.\n\n"
        f"Diff:\n{diff_text}"
    )
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": "openai/gpt-oss-120b",
        "messages": [{"role": "user", "content": prompt}]
    }
    for attempt in range(3):
        started = time.monotonic()
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=body,
            timeout=30,
        )
        logger.info("Groq API status=%s elapsed=%.2fs", response.status_code, time.monotonic() - started)
        if response.status_code == 429:
            if attempt < 2:
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2 ** attempt
                except ValueError:
                    try:
                        retry_time = parsedate_to_datetime(retry_after)
                        if retry_time.tzinfo is None:
                            retry_time = retry_time.replace(tzinfo=timezone.utc)
                        delay = max(0, (retry_time - datetime.now(timezone.utc)).total_seconds())
                    except (TypeError, ValueError, OverflowError):
                        delay = 2 ** attempt
                time.sleep(max(0, delay))
                continue
            response.raise_for_status()
        response.raise_for_status()
        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ValueError("Groq response did not contain choices[0].message.content") from exc
        if not isinstance(content, str):
            raise ValueError("Groq response content must be a string")
        return content
    raise RuntimeError("Groq request failed after retries")
