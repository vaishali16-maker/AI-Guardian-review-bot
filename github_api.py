import requests
import time
from github_auth import get_installation_token

# Make a request to the GitHub API with retry logic for rate limiting
def make_request_with_retry(method, url, headers, json_body=None, max_retries=3):
    for attempt in range(max_retries):
        if method == "GET":
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, json=json_body)
        if response.status_code == 429:
            wait_time = 2 ** attempt 
            print(f"⚠️ Rate limited. Retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(wait_time)
            continue
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining is not None and int(remaining) < 10:
            print(f"⚠️ Warning: only {remaining} GitHub API requests remaining this hour")
        return response
    print("❌ Max retries reached, giving up on this request")
    return response

# Fetch the diff of a pull request
def fetch_pr_diff(owner, repo, pr_number):
    token = get_installation_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files'
    response = make_request_with_retry("GET", url, headers)
    files = response.json()
    for file in files:
        print(file['filename'])
        print(file.get('patch', 'No diff available'))
        print('---')
    return files

# Post a comment on a pull request
def post_pr_comment(owner, repo, pr_number, comment_text):
    token = get_installation_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments'
    body = {'body': comment_text}
    response = make_request_with_retry("POST", url, headers, json_body=body)
    print(response.status_code)
    return response.json()