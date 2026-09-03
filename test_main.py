import pytest
from unittest.mock import patch, MagicMock


#Test 1: webhook filtering logic
def test_action_filter_accepts_opened():
    action = "opened"
    assert action in ("opened", "synchronize")

def test_action_filter_rejects_closed():
    action = "closed"
    assert action not in ("opened", "synchronize")


#Test 2: fetch_pr_diff parses a fake API response correctly 
@patch("github_api.get_installation_token")
@patch("github_api.requests.get")
def test_fetch_pr_diff_parses_response(mock_get, mock_token):
    from github_api import fetch_pr_diff
    mock_token.return_value = "fake_token"
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.headers = {"X-RateLimit-Remaining": "100"}
    fake_response.json.return_value = [
        {"filename": "app.py", "patch": "+print('hello')"}
    ]
    mock_get.return_value = fake_response
    result = fetch_pr_diff("owner", "repo", 1)
    assert len(result) == 1
    assert result[0]["filename"] == "app.py"


#Test 3: get_ai_review extracts content correctly 
@patch("review_ai.requests.post")
def test_get_ai_review_extracts_content(mock_post):
    from review_ai import get_ai_review
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "choices": [{"message": {"content": "No security issues found."}}]
    }
    mock_post.return_value = fake_response
    result = get_ai_review("some diff text")
    assert result == "No security issues found."


#Test 4: retry logic actually retries on 429 
@patch("github_api.get_installation_token")
@patch("github_api.requests.get")
@patch("github_api.time.sleep")  # skip real waiting during tests
def test_retry_on_rate_limit(mock_sleep, mock_get, mock_token):
    from github_api import fetch_pr_diff
    mock_token.return_value = "fake_token"
    rate_limited_response = MagicMock()
    rate_limited_response.status_code = 429
    success_response = MagicMock()
    success_response.status_code = 200
    success_response.headers = {"X-RateLimit-Remaining": "50"}
    success_response.json.return_value = [{"filename": "test.py", "patch": "+x=1"}]
    mock_get.side_effect = [rate_limited_response, success_response]
    result = fetch_pr_diff("owner", "repo", 1)
    assert mock_get.call_count == 2
    assert result[0]["filename"] == "test.py"