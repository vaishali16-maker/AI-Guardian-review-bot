import html
import re

from github_api import COMMENT_MARKER
from review_ai import SEVERITY_ORDER


def _markdown_text(value):
    value = html.escape(value, quote=False).replace("\r", " ").replace("\n", " ")
    value = value.replace("@", "@\u200b").replace("://", ":\u200b//")
    return re.sub(r"([\\`*_{}\[\]().!|>~-])", r"\\\1", value)


def _code_fence(code):
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", code)), default=0)
    return "`" * max(3, longest_run + 1)


def render_review(findings, skipped_files=None, truncated_files=None, error=None):
    """Render findings as Markdown with isolated prose and optional code blocks."""
    skipped_files = skipped_files or []
    truncated_files = truncated_files or []
    lines = [COMMENT_MARKER]

    if error:
        lines.append("\nGuardian could not parse the model response; no findings were posted.")
    elif not findings:
        lines.append("\nNo security findings were identified.")
    else:
        ordered = sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]])
        counts = {severity: sum(item["severity"] == severity for item in ordered) for severity in SEVERITY_ORDER}
        summary = ", ".join(f"{severity.title()}: {count}" for severity, count in counts.items())
        lines.append(f"\nSecurity findings: {summary}")

        for finding in ordered:
            location = _markdown_text(finding["file"])
            if finding["line"] is not None:
                location += f":{finding['line']}"
            cwe = _markdown_text(finding["cwe"] or "None")
            lines.extend([
                "",
                f"### {_markdown_text(finding['severity'].title())}: {_markdown_text(finding['title'])}",
                "",
                f"**Location:** {location}",
                "",
                f"**CWE:** {cwe}",
                "",
                f"**Explanation:** {_markdown_text(finding['explanation'])}",
                "",
                f"**Fix:** {_markdown_text(finding['fix'])}",
            ])

            fix_code = finding.get("fix_code")
            if fix_code:
                fence = _code_fence(fix_code)
                lines.extend(["", fence, fix_code, fence])

    if skipped_files:
        lines.extend(["", "Skipped files: " + ", ".join(_markdown_text(name) for name in skipped_files)])
    if truncated_files:
        lines.extend(["", "Truncated files: " + ", ".join(_markdown_text(name) for name in truncated_files)])
    return "\n".join(lines)
