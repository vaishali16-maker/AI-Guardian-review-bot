import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")


def get_ai_review(diff_text):
    prompt = (
        "You are a security-focused code reviewer. Review this code diff for "
        "security vulnerabilities, hardcoded secrets, injection risks, and unsafe "
        "patterns. Explain issues in plain language for a beginner. If there are "
        "no issues, say so briefly.\n\n"
        f"Diff:\n{diff_text}"
    )

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    body = {
        "model": "openai/gpt-oss-120b",
        "messages": [{"role": "user", "content": prompt}]
    }
    max_retries = 3
    for attempt in range(max_retries):
        response = requests.post("https://api.groq.com/openai/v1/chat/completions",headers=headers,json=body)
        if response.status_code == 429:
            wait_time = 2 ** attempt
            print(f"⚠️ Groq rate limited. Retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(wait_time)
            continue
        return response.json()["choices"][0]["message"]["content"]
    return "⚠️ AI review unavailable — rate limit exceeded after retries."