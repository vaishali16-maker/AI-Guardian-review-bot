import fnmatch
import os


LOCKFILES = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}
PER_FILE_CAP = 6000


def _skip_file(filename):
    normalized = filename.replace("\\", "/")
    base = os.path.basename(normalized)
    return (
        base in LOCKFILES
        or fnmatch.fnmatch(base, "*.min.js")
        or fnmatch.fnmatch(base, "*.map")
        or any(part in {"node_modules", "dist"} for part in normalized.split("/"))
    )


def build_diff(files, max_chars):
    """Return bounded diff text and explicit skipped/truncated file lists."""
    chunks = []
    skipped_files = []
    truncated_files = []
    used = 0

    for file in files:
        filename = file.get("filename", "unknown")
        if "patch" not in file or _skip_file(filename):
            skipped_files.append(filename)
            continue

        full_chunk = f"File: {filename}\n{file['patch']}\n\n"
        chunk = full_chunk[:PER_FILE_CAP]
        was_truncated = len(full_chunk) > PER_FILE_CAP
        remaining = max_chars - used
        if remaining <= 0:
            skipped_files.append(filename)
            continue
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
            was_truncated = True
        chunks.append(chunk)
        used += len(chunk)
        if was_truncated:
            truncated_files.append(filename)

    return "".join(chunks), skipped_files, truncated_files
