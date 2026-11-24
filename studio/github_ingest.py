"""Safe repository surface ingestion for Monkey's Paw Studio.

Supports:
1. `greenfield`  — No repository yet; returns canonical greenfield surface JSON.
2. `github_url`  — Shallow, blob-capped ephemeral `git clone` of public or private GitHub
                   repositories into a temporary folder that is immediately deleted in `finally`.
3. `local_path`  — Direct local path scan (enabled ONLY in local mode, disabled in cloud/Railway
                   deployments unless explicitly enabled via `STUDIO_ALLOW_LOCAL_PATHS=1`).
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.extract_repo_surface import DEFAULT_MAX_OUTPUT_BYTES, scan_repository  # noqa: E402

_SHORTHAND_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SAFE_BRANCH_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
CLONE_TIMEOUT_SECONDS = 45


def make_greenfield_surface(max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> dict[str, Any]:
    """Return a clean canonical greenfield surface payload."""
    return {
        "schema_version": "1.0",
        "tool": "monkey-paw/extract_repo_surface",
        "mode": "greenfield",
        "truncated": False,
        "byte_cap": max_bytes,
        "stats": {
            "scanned_code_files": 0,
            "skipped_ignored": 0,
            "skipped_sensitive_files": 0,
            "skipped_large_files": 0,
            "skipped_binary_files": 0,
            "extracted_counts": {
                "models": 0,
                "enums": 0,
                "routes": 0,
                "auth": 0,
                "workers": 0,
                "entrypoints": 0,
            },
        },
        "surface": {
            "models": [],
            "enums": [],
            "routes": [],
            "auth": [],
            "workers": [],
            "entrypoints": [],
        },
        "code_files": [],
    }


def parse_github_target(raw_input: str, explicit_branch: str = "") -> tuple[str, str, str]:
    """Validate and normalize a GitHub URL or `owner/repo` string.

    Returns `(https_clone_url, display_label, branch_or_empty)`.
    Raises `ValueError` on non-GitHub hosts, unsafe schemes, or injection attempts.
    """
    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("GitHub repository URL is empty.")

    branch = explicit_branch.strip()
    owner = ""
    repo = ""

    shorthand = _SHORTHAND_RE.match(cleaned)
    if shorthand:
        owner, repo = shorthand.group(1), shorthand.group(2)
    else:
        parsed = urlparse(cleaned)
        if parsed.scheme != "https":
            raise ValueError("Only 'https://github.com/<owner>/<repo>' URLs or 'owner/repo' shorthand are allowed.")
        if parsed.hostname not in {"github.com", "www.github.com"}:
            raise ValueError(f"Unsupported repository host '{parsed.hostname}'; expected github.com.")
        if parsed.username or parsed.password:
            raise ValueError("Do not embed credentials inside the GitHub URL; pass GITHUB_TOKEN separately.")

        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) < 2:
            raise ValueError("GitHub URL must include both owner and repository name (https://github.com/owner/repo).")
        owner, repo = parts[0], parts[1]
        if len(parts) >= 4 and parts[2] == "tree" and not branch:
            branch = "/".join(parts[3:])

    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo or owner in {".", ".."} or repo in {".", ".."}:
        raise ValueError("Invalid GitHub owner or repository name.")
    if owner.startswith("-") or repo.startswith("-"):
        raise ValueError("Owner and repository names cannot start with '-'.")
    if not _SAFE_SEGMENT_RE.match(owner) or not _SAFE_SEGMENT_RE.match(repo):
        raise ValueError("GitHub owner/repository contains invalid characters.")

    if branch:
        if branch.startswith("-") or ".." in branch or not _SAFE_BRANCH_RE.match(branch):
            raise ValueError(f"Invalid branch reference: {branch!r}")

    clone_url = f"https://github.com/{owner}/{repo}.git"
    label = f"github:{owner}/{repo}" + (f"@{branch}" if branch else "")
    return clone_url, label, branch


def ingest_repository_surface(
    *,
    source_type: str,
    repo_target: str = "",
    branch: str = "",
    github_token: str = "",
    allow_local_paths: bool = False,
    max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[dict[str, Any], str]:
    """Ingest a repository surface safely and return `(surface_payload, repo_label)`."""
    kind = (source_type or "greenfield").strip().lower()

    if kind == "greenfield" or not repo_target.strip():
        return make_greenfield_surface(max_bytes=max_bytes), "greenfield (no repository)"

    if kind == "local_path":
        if not allow_local_paths:
            raise PermissionError(
                "Local filesystem scanning is disabled on hosted deployments. Provide a GitHub repository URL or choose Greenfield."
            )
        target_path = Path(repo_target.strip()).expanduser().resolve()
        if not target_path.exists() or not target_path.is_dir():
            raise FileNotFoundError(f"Local repository folder not found: {repo_target}")
        payload, _ = scan_repository(target_path, max_bytes=max_bytes)
        return payload, f"local:{target_path.name}"

    if kind == "github_url":
        clone_url, label, resolved_branch = parse_github_target(repo_target, explicit_branch=branch)
        effective_token = (github_token or os.environ.get("GITHUB_TOKEN") or "").strip()

        tmp_parent = tempfile.mkdtemp(prefix="mp_gh_scan_")
        clone_dir = Path(tmp_parent) / "repo"
        try:
            cmd = ["git"]
            if effective_token:
                basic = base64.b64encode(f"x-access-token:{effective_token}".encode("utf-8")).decode("ascii")
                cmd.extend(["-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}"])

            cmd.extend(
                [
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "--no-tags",
                    "--filter=blob:limit=524288",
                ]
            )
            if resolved_branch:
                cmd.extend(["--branch", resolved_branch])
            cmd.extend(["--", clone_url, str(clone_dir)])

            env = {
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "",
            }

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=CLONE_TIMEOUT_SECONDS,
                    env=env,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"Timed out after {CLONE_TIMEOUT_SECONDS}s while cloning {label}.") from exc
            except FileNotFoundError as exc:
                raise RuntimeError("`git` CLI is required to scan remote GitHub repositories.") from exc

            if proc.returncode != 0:
                # Scrub any accidental token echoes before raising
                stderr_msg = proc.stderr.strip()
                if effective_token:
                    stderr_msg = stderr_msg.replace(effective_token, "[REDACTED]")
                raise RuntimeError(f"Unable to fetch {label}: {stderr_msg or 'git clone exited non-zero'}")

            payload, _ = scan_repository(clone_dir, max_bytes=max_bytes)
            return payload, label
        finally:
            shutil.rmtree(tmp_parent, ignore_errors=True)

    raise ValueError(f"Unknown repository source_type '{source_type}'; expected 'greenfield', 'github_url', or 'local_path'.")
