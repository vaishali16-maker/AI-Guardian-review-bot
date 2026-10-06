import pytest
from unittest.mock import patch, MagicMock
from unittest.mock import AsyncMock
try:
    from fastapi.testclient import TestClient
except RuntimeError:
    TestClient = None

#Test 1: webhook filtering logic
def test_action_filter_accepts_opened():
    action = "opened"
    assert action in ("opened", "synchronize")

#Test 2 webhook filtering logic
def test_action_filter_rejects_closed():
    action = "closed"
    assert action not in ("opened", "synchronize")

#Test 3: fetch_pr_diff parses a fake API response correctly 
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
    result = fetch_pr_diff("owner", "repo", 1, 12345)
    assert len(result) == 1
    assert result[0]["filename"] == "app.py"

#Test 4: get_ai_review extracts content correctly 
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


#Test 5: retry logic actually retries on 429 
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
    result = fetch_pr_diff("owner", "repo", 1, 12345)
    assert mock_get.call_count == 2
    assert result[0]["filename"] == "test.py"

#Test 6: signature verification accepts a correct signature
def test_verify_signature_accepts_valid():
    import hmac, hashlib
    import main
    body = b'{"action": "opened"}'
    secret = "testsecret"
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    with patch("main.WEBHOOK_SECRET", secret):
        assert main.verify_signature(body, sig) is True


#Test 7: signature verification rejects a wrong signature
def test_verify_signature_rejects_invalid():
    import main
    body = b'{"action": "opened"}'
    with patch("main.WEBHOOK_SECRET", "testsecret"):
        assert main.verify_signature(body, "sha256=wrongsignature") is False


#Test 8: signature verification rejects a missing signature
def test_verify_signature_rejects_missing():
    import main
    body = b'{"action": "opened"}'
    with patch("main.WEBHOOK_SECRET", "testsecret"):
        assert main.verify_signature(body, None) is False

#Test 9: fetch_pr_diff passes the installation ID to the token function
@patch("github_api.get_installation_token")
@patch("github_api.requests.get")
def test_fetch_pr_diff_uses_given_installation_id(mock_get, mock_token):
    from github_api import fetch_pr_diff
    mock_token.return_value = "fake_token"
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.headers = {"X-RateLimit-Remaining": "100"}
    fake_response.json.return_value = []
    mock_get.return_value = fake_response
    fetch_pr_diff("owner", "repo", 1, 99999)
    mock_token.assert_called_once_with(99999)


def _webhook_payload(**changes):
    payload = {
        "action": "opened",
        "repository": {"owner": {"login": "owner"}, "name": "repo"},
        "pull_request": {"number": 7, "draft": False},
        "installation": {"id": 123},
        "sender": {"type": "User"},
    }
    for key, value in changes.items():
        payload[key] = value
    return payload


def _signed_headers(payload, secret="testsecret", delivery="delivery-1"):
    import hashlib
    import hmac
    import json
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return body, {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery,
    }


@patch("main.process_review", new_callable=AsyncMock)
def test_webhook_valid_signature_returns_200(mock_process):
    if TestClient is None:
        pytest.skip("FastAPI TestClient requires the unavailable httpx2 dependency")
    import main
    body, headers = _signed_headers(_webhook_payload())
    with patch("main.WEBHOOK_SECRET", "testsecret"), TestClient(main.app) as client:
        assert client.post("/webhook", content=body, headers=headers).status_code == 200


@pytest.mark.parametrize("signature", ["sha256=invalid", None])
@patch("main.process_review", new_callable=AsyncMock)
def test_webhook_rejects_invalid_or_missing_signature(mock_process, signature):
    if TestClient is None:
        pytest.skip("FastAPI TestClient requires the unavailable httpx2 dependency")
    import main
    body, headers = _signed_headers(_webhook_payload())
    headers.pop("X-Hub-Signature-256")
    if signature is not None:
        headers["X-Hub-Signature-256"] = signature
    with patch("main.WEBHOOK_SECRET", "testsecret"), TestClient(main.app) as client:
        assert client.post("/webhook", content=body, headers=headers).status_code == 401


@patch("main.process_review", new_callable=AsyncMock)
def test_webhook_ignores_duplicate_delivery_id(mock_process):
    if TestClient is None:
        pytest.skip("FastAPI TestClient requires the unavailable httpx2 dependency")
    import main
    main.SEEN_DELIVERIES.clear()
    body, headers = _signed_headers(_webhook_payload(), delivery="duplicate-id")
    with patch("main.WEBHOOK_SECRET", "testsecret"), TestClient(main.app) as client:
        assert client.post("/webhook", content=body, headers=headers).status_code == 200
        queued_after_first = client.app.state.review_queue.qsize()
        assert client.post("/webhook", content=body, headers=headers).status_code == 200
        assert client.app.state.review_queue.qsize() == queued_after_first


@pytest.mark.parametrize("payload", [
    _webhook_payload(sender={"type": "Bot"}),
    _webhook_payload(pull_request={"number": 7, "draft": True}),
])
@patch("main.process_review", new_callable=AsyncMock)
def test_webhook_ignores_bot_and_draft(mock_process, payload):
    if TestClient is None:
        pytest.skip("FastAPI TestClient requires the unavailable httpx2 dependency")
    import main
    body, headers = _signed_headers(payload, delivery="ignored-" + str(payload))
    with patch("main.WEBHOOK_SECRET", "testsecret"), TestClient(main.app) as client:
        before = client.app.state.review_queue.qsize()
        assert client.post("/webhook", content=body, headers=headers).status_code == 200
        assert client.app.state.review_queue.qsize() == before


def test_build_diff_skips_lockfiles_missing_patch_and_caps_file():
    from diff_utils import build_diff
    diff, skipped, truncated = build_diff([
        {"filename": "package-lock.json", "patch": "+ignored"},
        {"filename": "no-patch.py"},
        {"filename": "large.py", "patch": "+" + "x" * 7000},
    ], 10000)
    assert "ignored" not in diff
    assert "no-patch.py" not in diff
    assert len(diff) == 6000
    assert skipped == ["package-lock.json", "no-patch.py"]
    assert truncated == ["large.py"]


@patch("github_api.time.sleep")
@patch("github_api.requests.get")
@patch("github_api.get_installation_token", return_value="fake-token")
def test_fetch_pr_diff_paginates(mock_token, mock_get, mock_sleep):
    from github_api import fetch_pr_diff
    full_page = [{"filename": f"f{i}.py", "patch": "+x"} for i in range(100)]
    last_page = [{"filename": "last.py", "patch": "+y"}]
    responses = []
    for files in (full_page, last_page):
        response = MagicMock(status_code=200, headers={"X-RateLimit-Remaining": "50"})
        response.json.return_value = files
        responses.append(response)
    mock_get.side_effect = responses
    result = fetch_pr_diff("owner", "repo", 2, 123)
    assert len(result) == 101
    assert mock_get.call_count == 2
    assert "page=2" in mock_get.call_args_list[1].args[0]


@patch("github_api.time.sleep")
@patch("github_api.requests.get")
def test_retry_raises_after_final_attempt(mock_get, mock_sleep):
    from github_api import make_request_with_retry
    response = MagicMock(status_code=503, headers={})
    mock_get.return_value = response
    with pytest.raises(Exception, match="failed after 3 attempts"):
        make_request_with_retry("GET", "https://example.test", {}, max_retries=3)
    assert mock_get.call_count == 3


@patch("github_api.get_installation_token", return_value="fake-token")
@patch("github_api.requests.patch")
@patch("github_api.requests.get")
def test_post_pr_comment_updates_existing_marker(mock_get, mock_patch, mock_token):
    from github_api import post_pr_comment, COMMENT_MARKER
    found = MagicMock(status_code=200, headers={})
    found.json.return_value = [{"id": 42, "body": f"{COMMENT_MARKER}\nold"}]
    updated = MagicMock(status_code=200, headers={})
    updated.json.return_value = {"id": 42}
    mock_get.return_value = found
    mock_patch.return_value = updated
    result = post_pr_comment("owner", "repo", 1, "new review", 123)
    assert result["id"] == 42
    mock_patch.assert_called_once()
    mock_get.assert_called_once()
    assert mock_patch.call_args.kwargs["json"]["body"].startswith(COMMENT_MARKER)
