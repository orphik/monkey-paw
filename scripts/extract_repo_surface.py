#!/usr/bin/env python3
"""Deterministic polyglot repository surface scanner for monkey-paw.

Scans a repository read-only for data models, database tables, enums, API routes,
authorization boundaries, background workers, and module entrypoints, writing a
byte-capped JSON summary to `.monkey-paw/surface.json`.

Safety invariants:
- Python 3.10+ stdlib only (zero pip dependencies).
- Read-only against application source files.
- Respects `.gitignore`; skips `node_modules`, `venv`, caches, binaries, and files > 512 KB.
- NEVER opens or emits `.env*`, private keys, credentials, or inline secret tokens.
- Degrades cleanly to `"mode": "greenfield"` (exit code 0) on empty or non-code directories.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_FILE_SIZE_BYTES = 512 * 1024  # 512 KB hard per-file ceiling
DEFAULT_MAX_OUTPUT_BYTES = 65_536  # 64 KB default JSON output cap
MIN_OUTPUT_BYTES = 512

HARD_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".monkey-paw",
        "node_modules",
        "bower_components",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "dist",
        "build",
        "out",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        "target",
        "vendor",
        "Pods",
        "coverage",
        "htmlcov",
        ".gradle",
        ".idea",
        ".vscode",
    }
)

BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".tiff",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".wasm",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".a",
        ".class",
        ".jar",
        ".war",
        ".pyc",
        ".pyo",
        ".pyd",
        ".whl",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp3",
        ".mp4",
        ".wav",
        ".mov",
        ".avi",
        ".mkv",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".parquet",
        ".feather",
        ".arrow",
        ".lockb",
    }
)

SENSITIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".crt",
        ".cer",
        ".der",
        ".asc",
        ".gpg",
        ".kdbx",
        ".tfstate",
        ".ovpn",
    }
)

SENSITIVE_EXACT_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".htpasswd",
        ".pgpass",
        "master.key",
        "credentials.json",
        "service-account.json",
        "service_account.json",
    }
)

SENSITIVE_GLOB_PATTERNS: tuple[str, ...] = (
    ".env.*",
    "*.env",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*credentials*.json",
    "*service-account*.json",
    "*service_account*.json",
    "client_secret*.json",
    ".secrets*",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.toml",
    "secrets.ini",
)

CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".prisma",
        ".sql",
        ".graphql",
        ".gql",
        ".go",
        ".rs",
        ".rb",
        ".java",
        ".kt",
        ".cs",
        ".php",
    }
)

SECRET_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"),
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/]+:[^@\s]+@[^\s\"'`]+"),
    re.compile(
        r"(?i)\b(password|passwd|secret|api_key|apikey|access_token|private_key|client_secret|auth_token)"
        r"\s*[:=]\s*['\"][^'\"]{4,}['\"]"
    ),
)


def scrub_secrets(value: str) -> str:
    """Remove any accidental inline credential or token patterns from extracted strings."""
    cleaned = value
    for pattern in SECRET_TOKEN_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned


def is_sensitive_path(rel_posix: str, name: str) -> bool:
    """Return True if a file must NEVER be opened or emitted."""
    lower_name = name.lower()
    if lower_name in SENSITIVE_EXACT_NAMES:
        return True
    if lower_name.startswith(".env"):
        return True
    _, ext = os.path.splitext(lower_name)
    if ext in SENSITIVE_EXTENSIONS:
        return True
    for glob_pat in SENSITIVE_GLOB_PATTERNS:
        if fnmatch.fnmatch(lower_name, glob_pat):
            return True
    parts = [p.lower() for p in rel_posix.split("/")]
    if any(p in {".secrets", "certs", "private_keys"} for p in parts[:-1]):
        return True
    return False


def is_openapi_file(name: str) -> bool:
    """Detect OpenAPI or Swagger specification files by filename."""
    lower = name.lower()
    if not lower.endswith((".json", ".yaml", ".yml")):
        return False
    return "openapi" in lower or "swagger" in lower


@dataclass(frozen=True)
class GitIgnoreRule:
    base_dir: str  # POSIX relative dir ("" for root)
    regex: re.Pattern[str]
    negated: bool
    dir_only: bool


def _compile_gitignore_pattern(pattern: str) -> re.Pattern[str]:
    """Translate a single gitignore glob pattern into a compiled regular expression."""
    anchored = "/" in pattern
    if pattern.startswith("/"):
        pattern = pattern[1:]

    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                if i + 2 < n and pattern[i + 2] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end != -1:
                bracket = pattern[i + 1 : end]
                if bracket.startswith("!"):
                    bracket = "^" + bracket[1:]
                out.append(f"[{bracket}]")
                i = end + 1
                continue
            out.append(r"\[")
        else:
            out.append(re.escape(ch))
        i += 1

    body = "".join(out)
    if anchored:
        full = f"^{body}(?:/.*)?$"
    else:
        full = f"^(?:.*/)?{body}(?:/.*)?$"
    return re.compile(full)


def parse_gitignore_file(gitignore_path: Path, base_dir: str) -> list[GitIgnoreRule]:
    """Parse a `.gitignore` file into deterministic rule objects."""
    rules: list[GitIgnoreRule] = []
    try:
        raw = gitignore_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rules

    for raw_line in raw.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # Unquoted trailing spaces are stripped per gitignore rules
        if not line.endswith("\\ "):
            line = line.rstrip(" ")
        if not line:
            continue

        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:]
        elif line.startswith("\\!"):
            line = line[1:]
        elif line.startswith("\\#"):
            line = line[1:]

        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
        if not line:
            continue

        rules.append(
            GitIgnoreRule(
                base_dir=base_dir,
                regex=_compile_gitignore_pattern(line),
                negated=negated,
                dir_only=dir_only,
            )
        )
    return rules


def is_gitignored(rel_posix: str, is_dir: bool, rules: list[GitIgnoreRule]) -> bool:
    """Evaluate active `.gitignore` rules in order (last match wins)."""
    ignored = False
    for rule in rules:
        if rule.base_dir:
            prefix = rule.base_dir + "/"
            if not rel_posix.startswith(prefix):
                continue
            sub_path = rel_posix[len(prefix) :]
        else:
            sub_path = rel_posix

        if rule.dir_only and not is_dir:
            # A dir_only rule still ignores files under an ignored directory,
            # though os.walk prunes ignored directories before descending.
            parts = sub_path.split("/")
            if len(parts) <= 1:
                continue
            parent_candidates = ["/".join(parts[:idx]) for idx in range(1, len(parts))]
            if any(rule.regex.match(pc) for pc in parent_candidates):
                ignored = not rule.negated
            continue

        if rule.regex.match(sub_path):
            ignored = not rule.negated
    return ignored


def read_safe_text_file(path: Path) -> tuple[str | None, str | None]:
    """Read a text file safely, rejecting >512KB and binary content.

    Returns (text, skip_reason) where skip_reason is None on success, or one of
    `'large'`, `'binary'`, `'io_error'`.
    """
    try:
        st = path.stat()
    except OSError:
        return None, "io_error"

    if st.st_size > MAX_FILE_SIZE_BYTES:
        return None, "large"

    if path.suffix.lower() in BINARY_EXTENSIONS:
        return None, "binary"

    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_SIZE_BYTES + 1)
    except OSError:
        return None, "io_error"

    if len(raw) > MAX_FILE_SIZE_BYTES:
        return None, "large"

    if b"\x00" in raw[:8192]:
        return None, "binary"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None, "binary"
    return text, None


def _make_item(
    name: str,
    kind: str,
    rel_file: str,
    line: int,
    detail: str = "",
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "name": scrub_secrets(name.strip())[:120],
        "kind": scrub_secrets(kind.strip())[:60],
        "file": rel_file,
        "line": max(1, int(line)),
    }
    if detail:
        item["detail"] = scrub_secrets(detail.strip())[:200]
    return item


# ---------------------------------------------------------------------------
# Polyglot Extractors
# ---------------------------------------------------------------------------


def _ast_expr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_expr_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _ast_expr_name(node.value)
    if isinstance(node, ast.Call):
        return _ast_expr_name(node.func)
    return ""


def _ast_const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def extract_python_surface(rel_file: str, text: str, buckets: dict[str, list[dict[str, Any]]]) -> None:
    """Extract Python models, enums, routes, auth dependencies, workers, and CLI entrypoints via AST."""
    try:
        tree = ast.parse(text, filename=rel_file)
    except SyntaxError:
        return

    http_verbs = {"get", "post", "put", "patch", "delete", "options", "head", "websocket"}
    enum_bases = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "TextChoices", "IntegerChoices"}
    model_base_hints = {"BaseModel", "SQLModel", "Base", "DeclarativeBase", "Model", "Document", "Schema"}
    auth_keywords = ("auth", "user", "admin", "role", "perm", "token", "jwt", "tenant", "org", "scope", "session", "apikey", "api_key")

    for node in ast.walk(tree):
        # Detect CLI `if __name__ == "__main__":`
        if isinstance(node, ast.If):
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.Eq)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
                and len(test.comparators) == 1
                and _ast_const_str(test.comparators[0]) == "__main__"
            ):
                buckets["entrypoints"].append(
                    _make_item(Path(rel_file).stem, "python_cli", rel_file, node.lineno, "CLI __main__ entrypoint")
                )

        # Classes: Models & Enums
        if isinstance(node, ast.ClassDef):
            base_names = [_ast_expr_name(b) for b in node.bases]
            short_bases = {b.split(".")[-1] for b in base_names if b}
            decorator_names = [_ast_expr_name(d) for d in node.decorator_list]
            short_decs = {d.split(".")[-1] for d in decorator_names if d}

            if short_bases & enum_bases:
                members: list[str] = []
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name) and not target.id.startswith("_"):
                                members.append(target.id)
                buckets["enums"].append(
                    _make_item(
                        node.name,
                        "python_enum",
                        rel_file,
                        node.lineno,
                        f"values=[{', '.join(members[:12])}]" if members else "",
                    )
                )
                continue

            is_dataclass = "dataclass" in short_decs
            is_orm_table = any(
                isinstance(stmt, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in stmt.targets)
                for stmt in node.body
            )
            matched_base = short_bases & model_base_hints
            if matched_base or is_dataclass or is_orm_table:
                fields: list[str] = []
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        fname = stmt.target.id
                        if not fname.startswith("_"):
                            ftype = _ast_expr_name(stmt.annotation)
                            fields.append(f"{fname}:{ftype}" if ftype else fname)
                    elif isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name) and not target.id.startswith("_"):
                                call_name = _ast_expr_name(stmt.value).split(".")[-1]
                                if call_name in {"Column", "mapped_column", "Field", "relationship", "ForeignKey"} or "Field" in call_name:
                                    fields.append(f"{target.id}:{call_name}")
                framework = "dataclass" if is_dataclass else ("sqlalchemy" if is_orm_table else next(iter(matched_base), "model").lower())
                buckets["models"].append(
                    _make_item(
                        node.name,
                        f"python_{framework}",
                        rel_file,
                        node.lineno,
                        f"fields=[{', '.join(fields[:12])}]" if fields else "",
                    )
                )

            # Check DRF permission_classes on APIViews/ViewSets
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "permission_classes":
                            buckets["auth"].append(
                                _make_item(
                                    f"{node.name}.permission_classes",
                                    "drf_permission",
                                    rel_file,
                                    stmt.lineno,
                                )
                            )

        # Functions & AsyncFunctions: Routes, Workers, Auth decorators/Depends
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = _ast_expr_name(dec)
                dec_leaf = dec_name.split(".")[-1] if dec_name else ""

                # FastAPI / Flask / Starlette routes
                if isinstance(dec, ast.Call) and dec_leaf in http_verbs | {"route", "api_route"}:
                    route_path = _ast_const_str(dec.args[0]) if dec.args else None
                    if route_path is not None:
                        methods = [dec_leaf.upper()]
                        if dec_leaf in {"route", "api_route"}:
                            methods = ["ROUTE"]
                            for kw in dec.keywords:
                                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                    extracted = [_ast_const_str(elt) for elt in kw.value.elts]
                                    clean_m = [m.upper() for m in extracted if m]
                                    if clean_m:
                                        methods = clean_m
                        for method in methods:
                            buckets["routes"].append(
                                _make_item(
                                    f"{method} {route_path}",
                                    "python_route",
                                    rel_file,
                                    node.lineno,
                                    f"handler={node.name}",
                                )
                            )

                # Auth decorators
                if dec_leaf in {
                    "login_required",
                    "permission_required",
                    "jwt_required",
                    "requires_auth",
                    "admin_required",
                    "staff_member_required",
                }:
                    buckets["auth"].append(
                        _make_item(f"@{dec_name} -> {node.name}", "python_auth_decorator", rel_file, node.lineno)
                    )

                # Worker / Queue decorators (Celery, Dramatiq, Temporal, RQ, Cron)
                if dec_leaf in {"task", "shared_task", "actor", "job", "cron"} or dec_name in {
                    "workflow.defn",
                    "activity.defn",
                }:
                    buckets["workers"].append(
                        _make_item(node.name, f"python_worker:{dec_leaf or dec_name}", rel_file, node.lineno)
                    )

            # Inspect parameter defaults for FastAPI `Depends(...)` / `Security(...)`
            all_defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
            for default_node in all_defaults:
                if isinstance(default_node, ast.Call):
                    call_leaf = _ast_expr_name(default_node.func).split(".")[-1]
                    if call_leaf in {"Depends", "Security"} and default_node.args:
                        dep_target = _ast_expr_name(default_node.args[0])
                        if dep_target and (
                            call_leaf == "Security"
                            or any(kw in dep_target.lower() for kw in auth_keywords)
                        ):
                            buckets["auth"].append(
                                _make_item(
                                    f"{call_leaf}({dep_target})",
                                    "fastapi_dependency",
                                    rel_file,
                                    node.lineno,
                                    f"endpoint={node.name}",
                                )
                            )

        # Django `path("...", view)` calls
        if isinstance(node, ast.Call):
            fn_leaf = _ast_expr_name(node.func).split(".")[-1]
            if fn_leaf in {"path", "re_path"} and len(node.args) >= 2 and rel_file.endswith("urls.py"):
                route_str = _ast_const_str(node.args[0])
                view_name = _ast_expr_name(node.args[1])
                if route_str is not None:
                    buckets["routes"].append(
                        _make_item(f"DJANGO /{route_str.lstrip('/')}", "django_url", rel_file, node.lineno, f"view={view_name}")
                    )


_PRISMA_BLOCK_RE = re.compile(r"^\s*(model|enum)\s+([A-Za-z_]\w*)\s*\{([\s\S]*?)^\s*\}", re.MULTILINE)


def extract_prisma_surface(rel_file: str, text: str, buckets: dict[str, list[dict[str, Any]]]) -> None:
    """Extract Prisma models and enums."""
    for match in _PRISMA_BLOCK_RE.finditer(text):
        block_kind, name, body = match.group(1), match.group(2), match.group(3)
        line = text.count("\n", 0, match.start()) + 1
        if block_kind == "enum":
            vals = [
                ln.strip().split()[0]
                for ln in body.splitlines()
                if ln.strip() and not ln.strip().startswith("//") and not ln.strip().startswith("@@")
            ]
            buckets["enums"].append(
                _make_item(name, "prisma_enum", rel_file, line, f"values=[{', '.join(vals[:12])}]")
            )
        else:
            fields: list[str] = []
            constraints: list[str] = []
            for raw_ln in body.splitlines():
                ln = raw_ln.strip()
                if not ln or ln.startswith("//"):
                    continue
                if ln.startswith("@@"):
                    constraints.append(ln.split("(")[0])
                    continue
                parts = ln.split()
                if len(parts) >= 2:
                    fname, ftype = parts[0], parts[1]
                    flags = [tok for tok in parts[2:] if tok.startswith(("@id", "@unique", "@relation"))]
                    tag = f"{fname}:{ftype}" + (f"({' '.join(flags)})" if flags else "")
                    fields.append(tag)
            detail = f"fields=[{', '.join(fields[:10])}]"
            if constraints:
                detail += f" constraints=[{', '.join(constraints[:4])}]"
            buckets["models"].append(_make_item(name, "prisma_model", rel_file, line, detail))


_SQL_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\"`\[]?[A-Za-z0-9_.\"`\]]+)\s*\(([\s\S]*?)\)\s*;",
    re.IGNORECASE,
)
_SQL_CREATE_ENUM_RE = re.compile(
    r"CREATE\s+TYPE\s+([\"`]?[A-Za-z0-9_.]+[\"`]?)\s+AS\s+ENUM\s*\(([\s\S]*?)\)\s*;",
    re.IGNORECASE,
)
_SQL_POLICY_RE = re.compile(
    r"CREATE\s+POLICY\s+([\"`]?[A-Za-z0-9_]+[\"`]?)\s+ON\s+([\"`]?[A-Za-z0-9_.]+[\"`]?)",
    re.IGNORECASE,
)
_SQL_RLS_RE = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?([\"`]?[A-Za-z0-9_.]+[\"`]?)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)


def extract_sql_surface(rel_file: str, text: str, buckets: dict[str, list[dict[str, Any]]]) -> None:
    """Extract SQL tables, enum types, and Row-Level Security policies."""
    for match in _SQL_CREATE_TABLE_RE.finditer(text):
        table_name = match.group(1).strip('"`[]')
        body = match.group(2)
        line = text.count("\n", 0, match.start()) + 1
        cols: list[str] = []
        for raw_ln in body.splitlines():
            ln = raw_ln.strip().rstrip(",")
            if not ln or ln.startswith("--"):
                continue
            upper = ln.upper()
            if upper.startswith(("PRIMARY KEY", "FOREIGN KEY", "CONSTRAINT", "UNIQUE", "CHECK", "INDEX")):
                cols.append(ln.split("(")[0].strip())
                continue
            tokens = ln.split()
            if len(tokens) >= 2:
                col_name = tokens[0].strip('"`[]')
                col_type = tokens[1]
                cols.append(f"{col_name}:{col_type}")
        buckets["models"].append(
            _make_item(table_name, "sql_table", rel_file, line, f"columns=[{', '.join(cols[:12])}]")
        )

    for match in _SQL_CREATE_ENUM_RE.finditer(text):
        enum_name = match.group(1).strip('"`')
        raw_vals = [v.strip().strip("'\"") for v in match.group(2).split(",") if v.strip()]
        line = text.count("\n", 0, match.start()) + 1
        buckets["enums"].append(
            _make_item(enum_name, "sql_enum", rel_file, line, f"values=[{', '.join(raw_vals[:12])}]")
        )

    for match in _SQL_POLICY_RE.finditer(text):
        pol, tbl = match.group(1).strip('"`'), match.group(2).strip('"`')
        line = text.count("\n", 0, match.start()) + 1
        buckets["auth"].append(_make_item(f"RLS Policy {pol} ON {tbl}", "sql_rls_policy", rel_file, line))

    for match in _SQL_RLS_RE.finditer(text):
        tbl = match.group(1).strip('"`')
        line = text.count("\n", 0, match.start()) + 1
        buckets["auth"].append(_make_item(f"RLS Enabled ON {tbl}", "sql_rls", rel_file, line))


_ZOD_OBJECT_RE = re.compile(r"(?:export\s+)?const\s+([A-Za-z_]\w*)\s*=\s*z\.object\s*\(\s*\{([\s\S]*?)\}\s*\)")
_ZOD_ENUM_RE = re.compile(r"(?:export\s+)?const\s+([A-Za-z_]\w*)\s*=\s*z\.enum\s*\(\s*\[([\s\S]*?)\]\s*\)")
_TS_ENUM_RE = re.compile(r"(?:export\s+)?enum\s+([A-Za-z_]\w*)\s*\{([\s\S]*?)\}")
_TS_INTERFACE_RE = re.compile(r"(?:export\s+)?interface\s+([A-Za-z_]\w*)\s*(?:extends\s+[^{]+)?\{([\s\S]*?)\}")
_DRIZZLE_TABLE_RE = re.compile(
    r"(?:export\s+)?const\s+([A-Za-z_]\w*)\s*=\s*(?:pgTable|mysqlTable|sqliteTable)\s*\(\s*['\"`]([^'\"`]+)['\"`]"
)
_TYPEORM_ENTITY_RE = re.compile(r"@Entity\s*\([^)]*\)\s*(?:export\s+)?class\s+([A-Za-z_]\w*)")
_EXPRESS_ROUTE_RE = re.compile(
    r"\b(?:app|router|server|api|v1|v2)\.(get|post|put|patch|delete)\s*\(\s*['\"`]([^'\"`]+)['\"`]([^\n;]*)"
)
_NEXT_APP_HANDLER_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b"
    r"|export\s+const\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*="
)
_TS_AUTH_RE = re.compile(
    r"\b(requireAuth|withAuth|authenticate|authorize|requireRole|requireAdmin|isAdmin|clerkMiddleware|"
    r"authMiddleware|verifyToken|checkPermission|getServerSession)\b"
)
_TS_WORKER_RE = re.compile(
    r"new\s+(Worker|Queue)\s*\(\s*['\"`]([^'\"`]+)['\"`]"
    r"|inngest\.createFunction\s*\(\s*\{\s*id\s*:\s*['\"`]([^'\"`]+)['\"`]"
    r"|cron\.schedule\s*\(\s*['\"`]([^'\"`]+)['\"`]"
)


def _derive_nextjs_route(rel_file: str) -> tuple[str | None, bool]:
    """Return (route_path, is_app_router) if `rel_file` is a Next.js API/Route handler."""
    parts = rel_file.split("/")
    # App router: .../app/<segments>/route.(ts|tsx|js|mjs)
    if len(parts) >= 2 and Path(parts[-1]).stem == "route" and "app" in parts[:-1]:
        app_idx = parts.index("app")
        segs = [s for s in parts[app_idx + 1 : -1] if not (s.startswith("(") and s.endswith(")"))]
        return "/" + "/".join(segs), True
    # Pages API router: .../pages/api/<segments>.(ts|tsx|js|mjs)
    if len(parts) >= 3 and "pages" in parts[:-2]:
        p_idx = parts.index("pages")
        if p_idx + 1 < len(parts) and parts[p_idx + 1] == "api":
            segs = parts[p_idx + 1 : -1] + [Path(parts[-1]).stem]
            if segs[-1] == "index":
                segs = segs[:-1]
            return "/" + "/".join(segs), False
    return None, False


def extract_ts_js_surface(rel_file: str, text: str, buckets: dict[str, list[dict[str, Any]]]) -> None:
    """Extract TypeScript/JavaScript/Zod models, enums, Express/Next routes, auth guards, and BullMQ/Inngest workers."""
    for match in _ZOD_OBJECT_RE.finditer(text):
        name, body = match.group(1), match.group(2)
        line = text.count("\n", 0, match.start()) + 1
        keys = re.findall(r"^\s*([A-Za-z_]\w*)\s*:", body, flags=re.MULTILINE)
        buckets["models"].append(
            _make_item(name, "zod_schema", rel_file, line, f"fields=[{', '.join(keys[:12])}]" if keys else "")
        )

    for match in _DRIZZLE_TABLE_RE.finditer(text):
        var_name, table_name = match.group(1), match.group(2)
        line = text.count("\n", 0, match.start()) + 1
        buckets["models"].append(_make_item(table_name, "drizzle_table", rel_file, line, f"symbol={var_name}"))

    for match in _TYPEORM_ENTITY_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        buckets["models"].append(_make_item(match.group(1), "typeorm_entity", rel_file, line))

    for match in _TS_INTERFACE_RE.finditer(text):
        name, body = match.group(1), match.group(2)
        if name.endswith("Props"):
            continue
        line = text.count("\n", 0, match.start()) + 1
        keys = re.findall(r"^\s*(?:readonly\s+)?([A-Za-z_]\w*)\??\s*:", body, flags=re.MULTILINE)
        buckets["models"].append(
            _make_item(name, "ts_interface", rel_file, line, f"fields=[{', '.join(keys[:12])}]" if keys else "")
        )

    for match in _ZOD_ENUM_RE.finditer(text):
        name, raw_vals = match.group(1), match.group(2)
        vals = [v.strip().strip("'\"`") for v in raw_vals.split(",") if v.strip()]
        line = text.count("\n", 0, match.start()) + 1
        buckets["enums"].append(
            _make_item(name, "zod_enum", rel_file, line, f"values=[{', '.join(vals[:12])}]")
        )

    for match in _TS_ENUM_RE.finditer(text):
        name, body = match.group(1), match.group(2)
        vals = [
            ln.split("=")[0].strip().rstrip(",")
            for ln in body.splitlines()
            if ln.strip() and not ln.strip().startswith("//")
        ]
        line = text.count("\n", 0, match.start()) + 1
        buckets["enums"].append(
            _make_item(name, "ts_enum", rel_file, line, f"values=[{', '.join(vals[:12])}]")
        )

    for match in _EXPRESS_ROUTE_RE.finditer(text):
        verb, route_path, rest = match.group(1).upper(), match.group(2), match.group(3)
        line = text.count("\n", 0, match.start()) + 1
        guards = _TS_AUTH_RE.findall(rest)
        detail = f"guards=[{', '.join(dict.fromkeys(guards))}]" if guards else ""
        buckets["routes"].append(_make_item(f"{verb} {route_path}", "js_http_route", rel_file, line, detail))

    next_route, is_app = _derive_nextjs_route(rel_file)
    if next_route is not None:
        if is_app:
            for match in _NEXT_APP_HANDLER_RE.finditer(text):
                verb = match.group(1) or match.group(2)
                line = text.count("\n", 0, match.start()) + 1
                buckets["routes"].append(_make_item(f"{verb} {next_route}", "nextjs_app_route", rel_file, line))
        else:
            buckets["routes"].append(_make_item(f"API {next_route}", "nextjs_pages_route", rel_file, 1))

    seen_auth_lines: set[tuple[str, int]] = set()
    for match in _TS_AUTH_RE.finditer(text):
        sym = match.group(1)
        line = text.count("\n", 0, match.start()) + 1
        if (sym, line) not in seen_auth_lines:
            seen_auth_lines.add((sym, line))
            buckets["auth"].append(_make_item(sym, "ts_auth_guard", rel_file, line))

    for match in _TS_WORKER_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if match.group(1):
            buckets["workers"].append(
                _make_item(match.group(2), f"bullmq_{match.group(1).lower()}", rel_file, line)
            )
        elif match.group(3):
            buckets["workers"].append(_make_item(match.group(3), "inngest_function", rel_file, line))
        elif match.group(4):
            buckets["workers"].append(_make_item(f"cron({match.group(4)})", "node_cron", rel_file, line))


def extract_openapi_surface(rel_file: str, text: str, buckets: dict[str, list[dict[str, Any]]]) -> None:
    """Extract routes, schemas, enums, and securitySchemes from OpenAPI JSON or YAML without PyYAML."""
    http_verbs = {"get", "post", "put", "patch", "delete", "options", "head"}
    if rel_file.lower().endswith(".json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return
        if not isinstance(doc, dict):
            return
        paths = doc.get("paths")
        if isinstance(paths, dict):
            for route_path, ops in paths.items():
                if isinstance(ops, dict):
                    for verb in ops:
                        if verb.lower() in http_verbs:
                            buckets["routes"].append(
                                _make_item(f"{verb.upper()} {route_path}", "openapi_route", rel_file, 1)
                            )
        components = doc.get("components")
        if isinstance(components, dict):
            schemas = components.get("schemas")
            if isinstance(schemas, dict):
                for sname, sdef in schemas.items():
                    if isinstance(sdef, dict) and isinstance(sdef.get("enum"), list):
                        vals = [str(v) for v in sdef["enum"][:12]]
                        buckets["enums"].append(
                            _make_item(sname, "openapi_enum", rel_file, 1, f"values=[{', '.join(vals)}]")
                        )
                    else:
                        props = list(sdef.get("properties", {}).keys())[:12] if isinstance(sdef, dict) else []
                        buckets["models"].append(
                            _make_item(sname, "openapi_schema", rel_file, 1, f"fields=[{', '.join(props)}]" if props else "")
                        )
            sec = components.get("securitySchemes")
            if isinstance(sec, dict):
                for sec_name, sec_def in sec.items():
                    stype = sec_def.get("type", "") if isinstance(sec_def, dict) else ""
                    buckets["auth"].append(_make_item(sec_name, "openapi_security", rel_file, 1, f"type={stype}"))
        return

    # Indentation-based YAML OpenAPI scanner
    section = ""
    subsection = ""
    current_path = ""
    for idx, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        key = stripped.strip()
        if indent == 0 and key.endswith(":"):
            section = key[:-1].strip()
            subsection = ""
            current_path = ""
            continue
        if section == "paths":
            if indent == 2 and key.endswith(":") and key.startswith("/"):
                current_path = key[:-1].strip().strip("'\"")
            elif indent == 4 and current_path and key.endswith(":"):
                verb = key[:-1].strip().lower()
                if verb in http_verbs:
                    buckets["routes"].append(
                        _make_item(f"{verb.upper()} {current_path}", "openapi_route", rel_file, idx)
                    )
        elif section == "components":
            if indent == 2 and key.endswith(":"):
                subsection = key[:-1].strip()
            elif indent == 4 and key.endswith(":"):
                item_name = key[:-1].strip().strip("'\"")
                if subsection == "schemas":
                    buckets["models"].append(_make_item(item_name, "openapi_schema", rel_file, idx))
                elif subsection == "securitySchemes":
                    buckets["auth"].append(_make_item(item_name, "openapi_security", rel_file, idx))


_GQL_BLOCK_RE = re.compile(r"^\s*(type|input|enum)\s+([A-Za-z_]\w*)[^{]*\{([\s\S]*?)^\s*\}", re.MULTILINE)
_GQL_AUTH_DIR_RE = re.compile(r"@(auth|authenticated|hasRole|requiresAuth|authorized)\b")


def extract_graphql_surface(rel_file: str, text: str, buckets: dict[str, list[dict[str, Any]]]) -> None:
    """Extract GraphQL Query/Mutation/Subscription operations, types/inputs, enums, and auth directives."""
    for match in _GQL_BLOCK_RE.finditer(text):
        kind, name, body = match.group(1), match.group(2), match.group(3)
        line = text.count("\n", 0, match.start()) + 1
        if kind == "enum":
            vals = [ln.strip().split()[0] for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            buckets["enums"].append(
                _make_item(name, "graphql_enum", rel_file, line, f"values=[{', '.join(vals[:12])}]")
            )
        elif name in {"Query", "Mutation", "Subscription"}:
            for offset, raw_ln in enumerate(body.splitlines()):
                ln = raw_ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                op_name = re.split(r"[\s(:]", ln, maxsplit=1)[0]
                if op_name:
                    buckets["routes"].append(
                        _make_item(f"GRAPHQL {name}.{op_name}", "graphql_operation", rel_file, line + offset)
                    )
        else:
            fields = [
                re.split(r"[\s(:]", ln.strip(), maxsplit=1)[0]
                for ln in body.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            buckets["models"].append(
                _make_item(name, f"graphql_{kind}", rel_file, line, f"fields=[{', '.join(fields[:12])}]")
            )

    for match in _GQL_AUTH_DIR_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        buckets["auth"].append(_make_item(f"@{match.group(1)}", "graphql_directive", rel_file, line))


# ---------------------------------------------------------------------------
# Main Repository Scanner & Deterministic Byte-Cap Serializer
# ---------------------------------------------------------------------------


def _serialize_within_cap(payload: dict[str, Any], max_bytes: int) -> bytes:
    """Serialize `payload` to UTF-8 JSON guaranteed to be `<= max_bytes`."""
    encoded = json.dumps(payload, indent=2, sort_keys=False).encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded

    payload["truncated"] = True
    bucket_order = ("code_files", "entrypoints", "models", "routes", "enums", "auth", "workers")

    # Iteratively halve or pop largest lists until under budget
    while len(encoded) > max_bytes:
        surface = payload.get("surface", {})
        candidates: list[tuple[int, str, list[Any]]] = []
        if isinstance(payload.get("code_files"), list) and payload["code_files"]:
            candidates.append((len(payload["code_files"]), "code_files", payload["code_files"]))
        for bname in bucket_order[1:]:
            blist = surface.get(bname)
            if isinstance(blist, list) and blist:
                candidates.append((len(blist), bname, blist))

        if not candidates:
            break

        # Pick the bucket with the most items; tie-break by bucket_order priority
        candidates.sort(key=lambda item: (item[0], -bucket_order.index(item[1])), reverse=True)
        _, _, target_list = candidates[0]
        drop_count = max(1, len(target_list) // 4)
        del target_list[-drop_count:]
        encoded = json.dumps(payload, indent=2, sort_keys=False).encode("utf-8")

    if len(encoded) > max_bytes:
        # Switch from pretty-printed to compact separators as final squeeze
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    if len(encoded) > max_bytes:
        minimal = {
            "schema_version": "1.0",
            "mode": payload["mode"],
            "truncated": True,
            "byte_cap": max_bytes,
            "stats": payload["stats"],
            "surface": {k: [] for k in ("models", "enums", "routes", "auth", "workers", "entrypoints")},
            "code_files": [],
        }
        encoded = json.dumps(minimal, separators=(",", ":")).encode("utf-8")
    return encoded


def scan_repository(repo_path: Path, max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    """Scan `repo_path` deterministically and return `(payload_dict, utf8_json_bytes)`."""
    if max_bytes < MIN_OUTPUT_BYTES:
        raise ValueError(f"max_bytes must be >= {MIN_OUTPUT_BYTES} (got {max_bytes})")

    repo_root = repo_path.resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        raise FileNotFoundError(f"Repository directory does not exist: {repo_path}")

    gitignore_rules: list[GitIgnoreRule] = []
    root_gitignore = repo_root / ".gitignore"
    if root_gitignore.is_file():
        gitignore_rules.extend(parse_gitignore_file(root_gitignore, ""))

    buckets: dict[str, list[dict[str, Any]]] = {
        "models": [],
        "enums": [],
        "routes": [],
        "auth": [],
        "workers": [],
        "entrypoints": [],
    }
    code_files: list[str] = []
    stats = {
        "scanned_code_files": 0,
        "skipped_ignored": 0,
        "skipped_sensitive_files": 0,
        "skipped_large_files": 0,
        "skipped_binary_files": 0,
    }

    for current_root, dirs, files in os.walk(repo_root, topdown=True):
        cur_path = Path(current_root)
        rel_dir = "" if cur_path == repo_root else cur_path.relative_to(repo_root).as_posix()

        # Load nested `.gitignore` if present in a subdirectory
        if rel_dir:
            nested_gi = cur_path / ".gitignore"
            if nested_gi.is_file():
                gitignore_rules.extend(parse_gitignore_file(nested_gi, rel_dir))

        # Deterministically filter & sort child directories in-place
        dirs.sort()
        kept_dirs: list[str] = []
        for dname in dirs:
            if dname in HARD_SKIP_DIRS or dname.lower().startswith(".env"):
                stats["skipped_ignored"] += 1
                continue
            d_rel = f"{rel_dir}/{dname}" if rel_dir else dname
            if is_gitignored(d_rel, is_dir=True, rules=gitignore_rules):
                stats["skipped_ignored"] += 1
                continue
            kept_dirs.append(dname)
        dirs[:] = kept_dirs

        files.sort()
        for fname in files:
            f_rel = f"{rel_dir}/{fname}" if rel_dir else fname

            # 1. Pre-open secret/credential path shield (strictly before stat/read)
            if is_sensitive_path(f_rel, fname):
                stats["skipped_sensitive_files"] += 1
                continue

            # 2. Gitignore filter
            if is_gitignored(f_rel, is_dir=False, rules=gitignore_rules):
                stats["skipped_ignored"] += 1
                continue

            ext = Path(fname).suffix.lower()
            openapi = is_openapi_file(fname)
            if ext not in CODE_EXTENSIONS and not openapi:
                continue

            full_file = cur_path / fname
            text, skip_reason = read_safe_text_file(full_file)
            if skip_reason == "large":
                stats["skipped_large_files"] += 1
                continue
            if skip_reason in {"binary", "io_error"} or text is None:
                stats["skipped_binary_files"] += 1
                continue

            stats["scanned_code_files"] += 1
            code_files.append(f_rel)

            if openapi:
                extract_openapi_surface(f_rel, text, buckets)
            elif ext == ".py":
                extract_python_surface(f_rel, text, buckets)
            elif ext == ".prisma":
                extract_prisma_surface(f_rel, text, buckets)
            elif ext == ".sql":
                extract_sql_surface(f_rel, text, buckets)
            elif ext in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
                extract_ts_js_surface(f_rel, text, buckets)
            elif ext in {".graphql", ".gql"}:
                extract_graphql_surface(f_rel, text, buckets)

    has_surface = stats["scanned_code_files"] > 0 or any(bool(v) for v in buckets.values())
    mode = "brownfield" if has_surface else "greenfield"

    counts = {k: len(v) for k, v in buckets.items()}
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "tool": "monkey-paw/extract_repo_surface",
        "mode": mode,
        "truncated": False,
        "byte_cap": max_bytes,
        "stats": {**stats, "extracted_counts": counts},
        "surface": buckets,
        "code_files": code_files,
    }
    encoded = _serialize_within_cap(payload, max_bytes=max_bytes)
    final_payload = json.loads(encoded.decode("utf-8"))
    return final_payload, encoded


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="extract_repo_surface.py",
        description="Deterministically scan a repository surface into .monkey-paw/surface.json (read-only).",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Target repository directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--out",
        default=".monkey-paw/surface.json",
        help="Output JSON file path (default: .monkey-paw/surface.json; pass '-' for stdout).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_OUTPUT_BYTES,
        help=f"Maximum UTF-8 byte size for output JSON (default: {DEFAULT_MAX_OUTPUT_BYTES}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        _, encoded = scan_repository(Path(args.repo), max_bytes=args.max_bytes)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.out == "-":
        sys.stdout.write(encoded.decode("utf-8") + "\n")
        return 0

    out_path = Path(args.out)
    if is_sensitive_path(out_path.as_posix(), out_path.name):
        print(f"ERROR: Refusing to write output to sensitive path: {out_path}", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
