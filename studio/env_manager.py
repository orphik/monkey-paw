"""Zero-dependency `.env` loader and localhost Environment Variable Manager for Studio.

Security boundaries:
- Whitelists strictly the 8 Studio configuration variables (`MANAGED_ENV_VARS`) so system
  variables (`PATH`, `PYTHONPATH`, etc.) can never be modified.
- Masks secret values on read (`AIza••••x9Q`) so raw keys are never echoed back over HTTP.
- Writing `.env` is enabled strictly on `localhost` (`allow_local_paths == True`) and
  hard-disabled (`HTTP 403`) on hosted/Railway deployments.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

MANAGED_ENV_VARS: tuple[dict[str, Any], ...] = (
    {
        "key": "GEMINI_API_KEY",
        "label": "Google Gemini API Key",
        "secret": True,
        "placeholder": "AIza... (from aistudio.google.com/apikey)",
    },
    {
        "key": "ANTHROPIC_API_KEY",
        "label": "Anthropic Claude API Key",
        "secret": True,
        "placeholder": "sk-ant-...",
    },
    {
        "key": "OPENAI_API_KEY",
        "label": "OpenAI API Key",
        "secret": True,
        "placeholder": "sk-...",
    },
    {
        "key": "OPENAI_COMPAT_BASE_URL",
        "label": "OpenAI-Compatible Base URL",
        "secret": False,
        "placeholder": "http://localhost:11434/v1 (Ollama / OpenRouter)",
    },
    {
        "key": "OPENAI_COMPAT_API_KEY",
        "label": "OpenAI-Compatible API Key",
        "secret": True,
        "placeholder": "Optional bearer token",
    },
    {
        "key": "STUDIO_DEFAULT_MODEL",
        "label": "Default Model Override",
        "secret": False,
        "placeholder": "Optional (e.g., gemini-3.8-flash)",
    },
    {
        "key": "GITHUB_TOKEN",
        "label": "GitHub Token (Private Repos)",
        "secret": True,
        "placeholder": "ghp_... or github_pat_... (Contents: Read)",
    },
    {
        "key": "STUDIO_PASSCODE",
        "label": "Studio Access Passcode",
        "secret": True,
        "placeholder": "Optional passcode lock",
    },
)

MANAGED_KEYS_MAP: dict[str, dict[str, Any]] = {item["key"]: item for item in MANAGED_ENV_VARS}
CLEAR_SENTINEL = "__CLEAR__"
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _unquote(raw_val: str) -> str:
    val = raw_val.strip()
    if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
        return val[1:-1]
    # Strip inline `#` comment on unquoted values
    if " #" in val:
        val = val.split(" #", 1)[0].rstrip()
    return val


def _format_dotenv_value(val: str) -> str:
    clean = val.replace("\r", "").replace("\n", "").strip()
    if any(ch in clean for ch in (' ', '#', '"', "'")):
        escaped = clean.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return clean


def mask_env_value(val: str, is_secret: bool) -> str:
    """Return a masked preview for secrets or raw text for non-secret settings."""
    if not val:
        return ""
    if not is_secret:
        return val
    if len(val) >= 10:
        return f"{val[:4]}****{val[-3:]}"
    return "****"


def parse_dotenv_keys(dotenv_path: Path) -> dict[str, str]:
    """Parse key-value pairs from a `.env` file without mutating `os.environ`."""
    if not dotenv_path.is_file():
        return {}
    try:
        raw = dotenv_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    found: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        found[m.group(1)] = _unquote(m.group(2))
    return found


def load_dotenv_into_environ(dotenv_path: Path, *, override: bool = False) -> int:
    """Load whitelisted Studio keys from `dotenv_path` into `os.environ`."""
    parsed = parse_dotenv_keys(dotenv_path)
    loaded = 0
    for key, val in parsed.items():
        if key not in MANAGED_KEYS_MAP or not val:
            continue
        if override or not os.environ.get(key):
            os.environ[key] = val
            loaded += 1
    return loaded


def get_env_status(dotenv_path: Path, *, editable_on_server: bool) -> dict[str, Any]:
    """Return masked status of all managed Studio environment variables."""
    dotenv_vals = parse_dotenv_keys(dotenv_path)
    items: list[dict[str, Any]] = []
    for meta in MANAGED_ENV_VARS:
        key = meta["key"]
        live_val = os.environ.get(key, "").strip()
        in_file = bool(dotenv_vals.get(key, "").strip())
        source = "none"
        if live_val:
            source = ".env" if (in_file and dotenv_vals.get(key) == live_val) else "environment"
        items.append(
            {
                "key": key,
                "label": meta["label"],
                "secret": meta["secret"],
                "placeholder": meta["placeholder"],
                "configured": bool(live_val),
                "masked_value": mask_env_value(live_val, meta["secret"]),
                "source": source,
            }
        )
    return {
        "editable_on_server": editable_on_server,
        "dotenv_path": dotenv_path.name if editable_on_server else "",
        "variables": items,
    }


def update_local_dotenv(dotenv_path: Path, updates: dict[str, Any]) -> dict[str, str]:
    """Update whitelisted Studio keys in `dotenv_path` and apply immediately to `os.environ`."""
    if not isinstance(updates, dict):
        raise ValueError("Environment updates payload must be a JSON object.")

    normalized_ops: dict[str, str | None] = {}
    for raw_key, raw_val in updates.items():
        key = str(raw_key).strip()
        if key not in MANAGED_KEYS_MAP:
            raise ValueError(f"Unsupported environment variable '{key}'.")
        if raw_val is None or str(raw_val) == CLEAR_SENTINEL:
            normalized_ops[key] = None
        else:
            cleaned = str(raw_val).replace("\r", "").replace("\n", "").strip()
            if cleaned:
                normalized_ops[key] = cleaned

    existing_lines: list[str] = []
    if dotenv_path.is_file():
        existing_lines = dotenv_path.read_text(encoding="utf-8", errors="replace").splitlines()

    handled_keys: set[str] = set()
    output_lines: list[str] = []
    for line in existing_lines:
        m = _ENV_LINE_RE.match(line)
        if not m or m.group(1) not in normalized_ops:
            output_lines.append(line)
            continue
        k = m.group(1)
        handled_keys.add(k)
        new_val = normalized_ops[k]
        if new_val is not None:
            output_lines.append(f"{k}={_format_dotenv_value(new_val)}")

    for k, new_val in normalized_ops.items():
        if k not in handled_keys and new_val is not None:
            output_lines.append(f"{k}={_format_dotenv_value(new_val)}")

    dotenv_path.parent.mkdir(parents=True, exist_ok=True)
    content = ("\n".join(output_lines).rstrip("\n") + "\n") if output_lines else ""
    dotenv_path.write_text(content, encoding="utf-8")
    try:
        os.chmod(dotenv_path, 0o600)
    except OSError:
        pass

    applied: dict[str, str] = {}
    for k, new_val in normalized_ops.items():
        if new_val is None:
            os.environ.pop(k, None)
            applied[k] = "cleared"
        else:
            os.environ[k] = new_val
            applied[k] = "updated"
    return applied
