"""Run the Guardian Review AI prompt benchmark. Live runs consume API quota."""

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import review_ai

MODEL = "openai/gpt-oss-120b"
ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Substrings used by the hardened scorer when a finding has no matching CWE.
CATEGORY_KEYWORDS = {
    "sql_injection": ("sql injection", "injection into sql", "sqli", "unparameterized", "unparameterised"),
    "hardcoded_secret": ("hardcoded", "hard coded", "embedded password", "embedded credential", "embedded secret"),
    "code_execution": ("code execution", "eval(", "exec(", "arbitrary python"),
    "command_injection": ("command injection", "shell injection", "os command", "shell=true"),
    "path_traversal": ("path traversal", "directory traversal", "outside the base", "escape the base"),
    "insecure_deserialization": ("deserializ", "pickle", "yaml.load", "unsafe yaml"),
    "weak_crypto": ("weak hash", "md5", "sha1", "sha 1", "insecure hash", "weak cryptographic"),
    "tls_verification_disabled": ("tls verification", "certificate verification", "certificate validation", "ssl verification", "verify=false"),
    "debug_mode_enabled": ("debug mode", "debug=true", "debugger"),
    "insecure_randomness": ("predictable random", "insecure random", "non cryptographic", "pseudo random", "random module"),
    "xss": ("cross site scripting", "xss", "unescaped", "html injection"),
    "ssrf": ("server side request forgery", "ssrf", "user controlled url", "internal service"),
}

ALL_VULNERABILITY_KEYWORDS = tuple(
    keyword
    for keyword_group in CATEGORY_KEYWORDS.values()
    for keyword in keyword_group
) + (
    "vulnerability", "vulnerable", "unsafe deserialization", "insecure transport",
    "remote code execution", "authentication bypass", "cross-site scripting",
)
NO_ISSUES_PATTERN = re.compile(
    r"\bno\b(?:\s+[a-z0-9_-]+){0,5}\s+\b(?:issues?|findings?|vulnerabilities)\b",
    re.IGNORECASE,
)


def hardened_detected(case, result):
    """Score a structured result for a vulnerable case using CWE or keywords."""
    accepted_cwes = {cwe.upper() for cwe in case.get("acceptable_cwes", [])}
    keywords = CATEGORY_KEYWORDS.get(case["category"], ())
    for finding in result.get("findings", []) if isinstance(result, dict) else []:
        cwe = finding.get("cwe")
        if isinstance(cwe, str) and cwe.upper() in accepted_cwes:
            return True
        text = normalize_text(f"{finding.get('title', '')} {finding.get('explanation', '')}")
        if any(keyword in text for keyword in keywords):
            return True
    return False


def is_hardened_false_positive(result):
    """A safe case is positive only when a medium-or-higher finding exists."""
    findings = result.get("findings", []) if isinstance(result, dict) else []
    return any(SEVERITY_RANK.get(finding.get("severity"), 0) >= 2 for finding in findings)


def naive_detected(case, text):
    keywords = CATEGORY_KEYWORDS.get(case["category"], ())
    normalized = normalize_text(text)
    return any(keyword in normalized for keyword in keywords)


def normalize_text(text):
    """Lowercase text, normalize separators, and collapse whitespace."""
    return " ".join(str(text).lower().replace("-", " ").replace("_", " ").split())


def is_naive_false_positive(text):
    """Count vulnerability names in naive prose, excluding plain no-issue claims."""
    remaining = normalize_text(NO_ISSUES_PATTERN.sub(" ", str(text).lower()))
    return any(normalize_text(keyword) in remaining for keyword in ALL_VULNERABILITY_KEYWORDS)


def score_output(case, output, prompt="hardened"):
    """Return the case's binary detection/false-positive outcome for one run."""
    if prompt == "naive":
        return naive_detected(case, output) if case["vulnerable"] else is_naive_false_positive(output)
    return hardened_detected(case, output) if case["vulnerable"] else is_hardened_false_positive(output)


def _naive_review(diff_text):
    prompt = (
        "You are a security-focused code reviewer. Review this code diff for "
        "security vulnerabilities, hardcoded secrets, injection risks, and unsafe "
        "patterns. Explain issues in plain language for a beginner. If there are "
        "no issues, say so briefly.\n\n"
        f"Diff:\n{diff_text}"
    )
    response = requests.post(
        ENDPOINT,
        headers={
            "Authorization": f"Bearer {review_ai.GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"model": MODEL, "messages": [{"role": "user", "content": prompt}]},
        timeout=30,
    )
    response.raise_for_status()
    try:
        return response.json()["choices"][0]["message"]["content"]
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise ValueError("Naive model response did not contain message content") from exc


def _run_once(case, prompt):
    code_lines = case["code"].splitlines()
    diff_text = (
        f"File: {case['id']}.py\n@@ -0,0 +1,{len(code_lines)} @@\n"
        + "\n".join(f"+{line}" for line in code_lines)
    )
    if prompt == "naive":
        return _naive_review(diff_text)
    return review_ai.get_ai_review(diff_text)


def _is_parse_error(output):
    return isinstance(output, dict) and "could not parse" in output.get("error", "").lower()


def run_cases(cases, prompt="hardened", sleeper=time.sleep):
    """Run each case three times, recording individual errors and decisions."""
    case_results = []
    for case in cases:
        runs = []
        for run_index in range(3):
            caught_exception = None
            try:
                output = _run_once(case, prompt)
                error = None
            except Exception as exc:  # Keep the batch moving when a call fails.
                caught_exception = exc
                output = None
                error = type(exc).__name__
            detected = score_output(case, output, prompt) if error is None else False
            run_record = {
                "run": run_index + 1,
                "output": output,
                "error": error,
                "parse_error": _is_parse_error(output),
                "positive": detected,
                "dropped": output.get("dropped", 0) if isinstance(output, dict) else 0,
            }
            if error is not None or (isinstance(output, dict) and output.get("error")):
                run_record["raw_model_output"] = (
                    output.get("raw_model_output") if isinstance(output, dict)
                    else getattr(caught_exception, "raw_model_output", None)
                )
                run_record["drop_reasons"] = (
                    output.get("drop_reasons", []) if isinstance(output, dict)
                    else getattr(caught_exception, "drop_reasons", [])
                )
            runs.append(run_record)
            if run_index < 2:
                sleeper(2)
        case_results.append({
            "id": case["id"],
            "vulnerable": case["vulnerable"],
            "category": case["category"],
            "runs": runs,
        })
    return case_results


def summarize(cases, case_results):
    """Aggregate run-level detection metrics and per-case consistency."""
    true_positive = false_negative = false_positive = true_negative = 0
    parse_errors = 0
    dropped_findings = 0
    per_category = {}
    consistent_cases = 0
    for case, result in zip(cases, case_results):
        decisions = [run["positive"] for run in result["runs"]]
        consistent_cases += bool(decisions) and all(value == decisions[0] for value in decisions)
        parse_errors += sum(run["parse_error"] for run in result["runs"])
        dropped_findings += sum(run.get("dropped", 0) for run in result["runs"])
        for decision in decisions:
            if case["vulnerable"]:
                true_positive += decision
                false_negative += not decision
                stats = per_category.setdefault(case["category"], {"detected": 0, "missed": 0})
                stats["detected"] += decision
                stats["missed"] += not decision
            else:
                false_positive += decision
                true_negative += not decision
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    for stats in per_category.values():
        total = stats["detected"] + stats["missed"]
        stats["recall"] = stats["detected"] / total if total else 0.0
    return {
        "recall": recall,
        "per_category": per_category,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "consistency": consistent_cases / len(case_results) if case_results else 0.0,
        "parse_errors": parse_errors,
        "dropped_findings": dropped_findings,
        "counts": {
            "true_positive_runs": true_positive,
            "false_negative_runs": false_negative,
            "false_positive_runs": false_positive,
            "true_negative_runs": true_negative,
            "safe_cases": sum(not case["vulnerable"] for case in cases),
            "vulnerable_cases": sum(case["vulnerable"] for case in cases),
        },
    }


def write_results(prompt, cases, results, summary):
    benchmark_dir = Path(__file__).resolve().parent
    cases_hash = hashlib.sha256((benchmark_dir / "cases.json").read_bytes()).hexdigest()
    payload = {"prompt": prompt, "summary": summary, "cases": results}
    (benchmark_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Guardian Review AI benchmark results",
        "",
        f"Cases SHA-256: `{cases_hash}`",
        "",
        "Labels frozen before results",
        "",
        "**Scoring differs by mode, and naive and hardened numbers are not directly comparable.** Hardened mode scores structured findings by accepted CWE or category keywords and counts safe-case findings at medium severity or higher. Naive mode scores vulnerable cases by category keywords in free text and safe cases by any named vulnerability after removing plain no-issue claims.",
        "",
        f"Prompt mode: **{prompt}**. Runs per case: **3**. Cases: **{len(cases)}**.",
        "",
        "Metrics are aggregated over individual runs except consistency, which is the fraction of cases whose three binary outcomes all agree.",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Overall recall | {summary['recall']:.1%} |",
        f"| Safe-case false-positive rate | {summary['false_positive_rate']:.1%} |",
        f"| Precision | {summary['precision']:.1%} |",
        f"| Three-run consistency | {summary['consistency']:.1%} |",
        f"| Parse errors | {summary['parse_errors']} |",
        f"| Dropped findings | {summary['dropped_findings']} |",
        "",
        "## Recall by vulnerable category",
        "",
        "| Category | Detected runs | Missed runs | Recall |",
        "|---|---:|---:|---:|",
    ]
    for category, stats in sorted(summary["per_category"].items()):
        lines.append(f"| {category} | {stats['detected']} | {stats['missed']} | {stats['recall']:.1%} |")
    (benchmark_dir / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Run only the first N cases")
    parser.add_argument("--prompt", choices=("hardened", "naive"), default="hardened")
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be non-negative")

    case_path = Path(__file__).resolve().parent / "cases.json"
    cases = json.loads(case_path.read_text(encoding="utf-8"))
    if args.limit is not None:
        cases = cases[:args.limit]
    results = run_cases(cases, args.prompt)
    summary = summarize(cases, results)
    write_results(args.prompt, cases, results, summary)
    print(f"Benchmark complete: {len(cases)} cases; recall {summary['recall']:.1%}; false-positive rate {summary['false_positive_rate']:.1%}")


if __name__ == "__main__":
    main()
