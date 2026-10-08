import json
from pathlib import Path

from benchmark.run_benchmark import score_output


def _vulnerable_case():
    return {
        "id": "unit_sqli",
        "vulnerable": True,
        "category": "sql_injection",
        "acceptable_cwes": ["CWE-89"],
    }


def test_benchmark_scores_detection_by_cwe():
    result = {"findings": [{"cwe": "CWE-89", "severity": "high", "title": "Database issue", "explanation": "Unsafe."}]}
    assert score_output(_vulnerable_case(), result) is True


def test_benchmark_scores_detection_by_category_keyword():
    result = {"findings": [{"cwe": None, "severity": "high", "title": "Unsafe query", "explanation": "This is SQL injection."}]}
    assert score_output(_vulnerable_case(), result) is True


def test_benchmark_scores_vulnerable_miss():
    assert score_output(_vulnerable_case(), {"findings": []}) is False


def test_benchmark_scores_safe_false_positive():
    case = {"id": "safe_test", "vulnerable": False, "category": "safe", "acceptable_cwes": []}
    result = {"findings": [{"severity": "medium", "title": "Possible issue"}]}
    assert score_output(case, result) is True


def test_benchmark_scores_safe_clean():
    case = {"id": "safe_test", "vulnerable": False, "category": "safe", "acceptable_cwes": []}
    assert score_output(case, {"findings": [{"severity": "low"}]}) is False
    assert score_output(case, {"findings": []}) is False


def test_benchmark_cases_are_valid_unique_and_sufficiently_labeled():
    path = Path(__file__).parent / "benchmark" / "cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(cases, list)
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids))
    assert all(isinstance(case.get("code"), str) and case["code"].strip() for case in cases)
    assert all(isinstance(case.get("acceptable_cwes"), list) for case in cases)
    assert sum(case["vulnerable"] for case in cases) >= 20
    assert sum(not case["vulnerable"] for case in cases) >= 12
    assert all(5 <= len(case["code"].splitlines()) <= 25 for case in cases)


def test_naive_mode_scores_free_text_differently():
    from benchmark.run_benchmark import score_output
    assert score_output(_vulnerable_case(), "Possible SQL injection", "naive") is True
    safe = {"id": "safe", "vulnerable": False, "category": "safe", "acceptable_cwes": []}
    assert score_output(safe, "No issues found.", "naive") is False
    assert score_output(safe, "The code contains SQL injection.", "naive") is True


def test_keyword_matching_normalizes_case_hyphens_and_underscores():
    from benchmark.run_benchmark import score_output
    result = {"findings": [{"title": "Cross-Site_Scripting", "explanation": "Detected."}]}
    case = {"vulnerable": True, "category": "xss", "acceptable_cwes": []}
    assert score_output(case, result) is True


def test_hardened_keywords_do_not_match_fix_fields():
    result = {"findings": [{
        "title": "Unsafe output",
        "explanation": "The text is escaped.",
        "fix": "Prevent cross site scripting by using html.escape.",
        "fix_code": "# cross site scripting",
    }]}
    case = {"vulnerable": True, "category": "xss", "acceptable_cwes": []}
    assert score_output(case, result) is False


def test_dataset_snippets_contain_no_comments():
    cases = json.loads((Path(__file__).parent / "benchmark" / "cases.json").read_text(encoding="utf-8"))
    for case in cases:
        assert not any(line.lstrip().startswith("#") or " # " in line for line in case["code"].splitlines()), case["id"]


def test_safe_ssrf_requests_disable_redirects():
    cases = json.loads((Path(__file__).parent / "benchmark" / "cases.json").read_text(encoding="utf-8"))
    case = next(item for item in cases if item["id"] == "safe_ssrf_01")
    calls = [line for line in case["code"].splitlines() if "requests.get(" in line]
    assert calls
    assert all("allow_redirects=False" in line for line in calls)


def test_added_file_patch_uses_correct_line_count(monkeypatch):
    from benchmark import run_benchmark
    captured = []
    monkeypatch.setattr(run_benchmark.review_ai, "get_ai_review", lambda diff: captured.append(diff) or {"findings": []})
    case = {"id": "patch_case", "code": "first = 1\nsecond = 2\n", "category": "safe", "vulnerable": False}
    run_benchmark._run_once(case, "hardened")
    assert captured == ["File: patch_case.py\n@@ -0,0 +1,2 @@\n+first = 1\n+second = 2"]


def test_validation_error_run_records_raw_output_and_drop_reasons(monkeypatch):
    from benchmark import run_benchmark
    monkeypatch.setattr(run_benchmark, "_run_once", lambda case, prompt: {
        "findings": [],
        "error": "model findings failed validation",
        "dropped": 2,
        "raw_model_output": '{"findings": [...]}',
        "drop_reasons": [{"field": "severity", "type": "str"}],
    })
    case = {"id": "failed", "code": "pass", "vulnerable": True, "category": "sql_injection"}
    results = run_benchmark.run_cases([case], sleeper=lambda delay: None)
    run = results[0]["runs"][0]
    assert run["raw_model_output"] == '{"findings": [...]}'
    assert run["drop_reasons"] == [{"field": "severity", "type": "str"}]
    assert run["dropped"] == 2
    assert run["positive"] is False
    assert run_benchmark.summarize([case], results)["dropped_findings"] == 6


def test_raised_run_error_records_available_diagnostics(monkeypatch):
    from benchmark import run_benchmark

    def fail(case, prompt):
        error = RuntimeError("request failed")
        error.raw_model_output = "raw diagnostic output"
        error.drop_reasons = [{"field": "title", "type": "NoneType"}]
        raise error

    monkeypatch.setattr(run_benchmark, "_run_once", fail)
    case = {"id": "failed", "code": "pass", "vulnerable": False, "category": "safe"}
    result = run_benchmark.run_cases([case], sleeper=lambda delay: None)[0]["runs"][0]
    assert result["error"] == "RuntimeError"
    assert result["raw_model_output"] == "raw diagnostic output"
    assert result["drop_reasons"] == [{"field": "title", "type": "NoneType"}]
