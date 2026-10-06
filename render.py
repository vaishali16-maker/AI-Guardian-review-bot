import html
import re

from github_api import COMMENT_MARKER
from review_ai import SEVERITY_ORDER


def _markdown_text(value):
    value = html.escape(value, quote=False).replace("\r", " ").replace("\n", " ")
    value = value.replace("@", "@\u200b").replace("://", ":\u200b//")
    return re.sub(r"([\\`*_{}\[\]().!|>~-])", r"\\\1", value)


def _safe_code(value):
    return value


def _contains_code(value):
    return "\n" in value or bool(re.search(r"(?:[{};]|=>|\b(?:const|let|var|def|function|return|SELECT|INSERT|UPDATE)\b)", value))


def _fix_markdown(fix):
    if _contains_code(fix):
        longest_fence = max((len(match.group(0)) for match in re.finditer(r"`+", fix)), default=0)
        fence = "`" * max(3, longest_fence + 1)
        return f"{fence}\n{_safe_code(fix)}\n{fence}"
    return _markdown_text(fix)


def render_review(findings, skipped_files=None, truncated_files=None, error=None):
    """Render validated findings as a safe, marked-up PR comment."""
    skipped_files = skipped_files or []
    truncated_files = truncated_files or []
    lines = [COMMENT_MARKER]
    if error:
        lines.append("Guardian could not parse the model response; no findings were posted.")
    elif not findings:
        lines.append("No security findings were identified.")
    else:
        ordered = sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]])
        counts = {severity: sum(f["severity"] == severity for f in ordered) for severity in SEVERITY_ORDER}
        lines.append("Security findings: " + ", ".join(f"{severity.title()}: {count}" for severity, count in counts.items()))
        for finding in ordered:
            location = _markdown_text(finding["file"])
            if finding["line"] is not None:
                location += f":{finding['line']}"
            cwe = _markdown_text(finding["cwe"] or "None")
            lines.extend([
                "",
                f"### {_markdown_text(finding['severity'].title())}: {_markdown_text(finding['title'])}",
                f"**Location:** {location}  ",
                f"**CWE:** {cwe}  ",
                f"**Explanation:** {_markdown_text(finding['explanation'])}  ",
                f"**Fix:** {_fix_markdown(finding['fix'])}",
            ])
    if skipped_files:
        lines.extend(["", "Skipped files: " + ", ".join(_markdown_text(name) for name in skipped_files)])
    if truncated_files:
        lines.extend(["Truncated files: " + ", ".join(_markdown_text(name) for name in truncated_files)])
    return "\n".join(lines)
