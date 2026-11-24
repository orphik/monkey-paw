"""Multi-provider LLM & Deterministic Referee Engine for Monkey's Paw Studio.

Supports:
- `gemini`            : Google Gemini REST API (`GEMINI_API_KEY` or BYOK)
- `anthropic`         : Anthropic Messages API (`ANTHROPIC_API_KEY` or BYOK)
- `openai`            : OpenAI Chat Completions API (`OPENAI_API_KEY` or BYOK)
- `openai_compatible` : Custom base URL (`Ollama`, `OpenRouter`, `vLLM`)
- `demo`              : Zero-API-key Deterministic Referee & Backlog Synthesis Engine

Every generated findings payload is strictly gated through `scripts/validate_findings.py`
with an automatic repair retry if an LLM emits generic filler or misses brownfield citations.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.compile_locked_spec import infer_title, resolve_finding_choice  # noqa: E402
from scripts.validate_findings import VALID_EXPLOIT_CLASSES, validate_findings_data  # noqa: E402
from studio.backlog_compiler import get_preset_levels, normalize_backlog_tree  # noqa: E402

DEFAULT_MODELS: dict[str, str] = {
    "gemini": "gemini-3.8-flash",
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4.1-mini",
    "openai_compatible": "llama3.1",
    "demo": "deterministic-referee-v1",
}

LLM_TIMEOUT_SECONDS = 75


def detect_server_providers() -> dict[str, bool]:
    """Report which LLM providers have server-side environment keys configured (booleans only)."""
    return {
        "gemini": bool(os.environ.get("GEMINI_API_KEY", "").strip()),
        "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
        "openai": bool(os.environ.get("OPENAI_API_KEY", "").strip()),
        "openai_compatible": bool(os.environ.get("OPENAI_COMPAT_BASE_URL", "").strip()),
        "demo": True,
    }


def resolve_provider_config(raw_cfg: dict[str, Any] | None) -> dict[str, str]:
    """Resolve effective provider, model, base_url, and API key from request or environment."""
    cfg = raw_cfg or {}
    requested = str(cfg.get("provider") or "auto").strip().lower()
    byok = str(cfg.get("api_key") or "").strip()
    custom_model = str(cfg.get("model") or "").strip()
    custom_url = str(cfg.get("base_url") or os.environ.get("OPENAI_COMPAT_BASE_URL") or "").strip()

    if requested == "auto":
        if byok:
            requested = "gemini" if byok.startswith("AIza") else ("anthropic" if byok.startswith("sk-ant-") else "openai")
        elif os.environ.get("GEMINI_API_KEY", "").strip():
            requested = "gemini"
        elif os.environ.get("ANTHROPIC_API_KEY", "").strip():
            requested = "anthropic"
        elif os.environ.get("OPENAI_API_KEY", "").strip():
            requested = "openai"
        elif custom_url:
            requested = "openai_compatible"
        else:
            requested = "demo"

    if requested == "demo":
        return {"provider": "demo", "model": DEFAULT_MODELS["demo"], "api_key": "", "base_url": ""}

    env_key_map = {
        "gemini": "GEMINI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "openai_compatible": "OPENAI_COMPAT_API_KEY",
    }
    if requested not in env_key_map:
        raise ValueError(f"Unsupported provider '{requested}'.")

    api_key = byok or os.environ.get(env_key_map[requested], "").strip()
    if requested != "openai_compatible" and not api_key:
        raise ValueError(
            f"No API key configured for provider '{requested}'. Enter a key in Provider Settings or choose 'Deterministic Sandbox (No Key)'."
        )
    if requested == "openai_compatible" and not custom_url:
        raise ValueError("Provide a Base URL (e.g., http://localhost:11434/v1) for openai_compatible mode.")

    model = custom_model or os.environ.get("STUDIO_DEFAULT_MODEL", "").strip() or DEFAULT_MODELS[requested]
    return {
        "provider": requested,
        "model": model,
        "api_key": api_key,
        "base_url": custom_url,
    }


def _extract_json_object(raw_text: str) -> Any:
    """Extract a JSON object from raw model output (stripping markdown code fences if present)."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end > start:
            return json.loads(cleaned[start : end + 1])
        raise


def _call_llm_json(system_prompt: str, user_prompt: str, provider_cfg: dict[str, str]) -> dict[str, Any]:
    """Invoke the configured LLM provider via stdlib HTTPS and parse JSON output."""
    provider = provider_cfg["provider"]
    model = provider_cfg["model"]
    api_key = provider_cfg["api_key"]

    if provider == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        raw = _execute_http(req, api_key)
        candidates = raw.get("candidates") or []
        text = candidates[0]["content"]["parts"][0]["text"]
        return _extract_json_object(text)

    if provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": model,
            "max_tokens": 4096,
            "temperature": 0.2,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt + "\n\nRespond with valid JSON only."}],
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        raw = _execute_http(req, api_key)
        blocks = raw.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        return _extract_json_object(text)

    # OpenAI or OpenAI-compatible
    base = provider_cfg["base_url"].rstrip("/") if provider == "openai_compatible" else "https://api.openai.com/v1"
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload: dict[str, Any] = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    if provider == "openai":
        payload["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    raw = _execute_http(req, api_key)
    text = raw["choices"][0]["message"]["content"]
    return _extract_json_object(text)


def _execute_http(req: urllib.request.Request, secret_to_scrub: str) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")[:400]
        except OSError:
            pass
        finally:
            exc.close()
        msg = f"Upstream LLM HTTP {exc.code}: {err_body}"
        if secret_to_scrub:
            msg = msg.replace(secret_to_scrub, "[REDACTED]")
        raise RuntimeError(msg) from exc
    except urllib.error.URLError as exc:
        msg = f"Upstream LLM network error: {exc.reason}"
        if secret_to_scrub:
            msg = msg.replace(secret_to_scrub, "[REDACTED]")
        raise RuntimeError(msg) from exc


# ---------------------------------------------------------------------------
# Deterministic Zero-Key Sandbox Referee & Backlog Synthesizer
# ---------------------------------------------------------------------------


def _collect_sample_citations(surface_payload: dict[str, Any]) -> list[str]:
    surface = surface_payload.get("surface") or {}
    cits: list[str] = []
    for bucket in ("routes", "models", "workers", "auth", "enums", "entrypoints"):
        for item in surface.get(bucket) or []:
            ref = f"{item['file']}:{item['line']}"
            if ref not in cits:
                cits.append(ref)
            if len(cits) >= 8:
                return cits
    for cf in surface_payload.get("code_files") or []:
        if cf not in cits:
            cits.append(cf)
        if len(cits) >= 6:
            break
    return cits


def _extract_prd_sentences(prd_text: str) -> list[str]:
    sentences: list[str] = []
    for raw_ln in prd_text.splitlines():
        ln = raw_ln.strip().lstrip("#-*0123456789. ").strip()
        if len(ln) >= 12:
            for chunk in re.split(r"(?<=[.!?])\s+", ln):
                c = chunk.strip()
                if len(c) >= 12:
                    sentences.append(c[:180])
    if not sentences:
        sentences.append(prd_text.strip()[:160] or "Implement requested user workflow and state transitions.")
    return sentences


def _build_deterministic_findings(prd_text: str, surface_payload: dict[str, Any]) -> dict[str, Any]:
    """Synthesize 3-4 schema-valid Monkey's Paw findings grounded in the PRD text and surface.json."""
    mode = surface_payload.get("mode", "greenfield")
    title = infer_title(prd_text, {}, fallback_name="PRD Specification")
    sentences = _extract_prd_sentences(prd_text)
    cits = _collect_sample_citations(surface_payload) if mode == "brownfield" else []

    def _cits_slice(idx: int) -> list[str]:
        if mode != "brownfield":
            return []
        if not cits:
            return ["README.md:1"]
        start = idx % len(cits)
        picked = [cits[start]]
        if len(cits) > 1:
            picked.append(cits[(start + 1) % len(cits)])
        return picked

    lower_prd = prd_text.lower()
    has_batch = any(w in lower_prd for w in ("batch", "bulk", "all ", "export", "import", "sync", "retry", "webhook", "list"))

    findings: list[dict[str, Any]] = [
        {
            "id": "MP-001",
            "title": "Concurrent Request & Duplicate Submission Race",
            "exploit_class": "concurrency_race",
            "spec_quote": sentences[0],
            "monkeys_paw_grant": (
                "A literal coding agent reads current state in application memory and writes updates without row-level "
                "locking or idempotency keys; double-clicks or parallel retries pass validation simultaneously and create duplicate mutations."
            ),
            "repo_citations": _cits_slice(0),
            "eng_options": {
                "option_a": {
                    "label": "Pessimistic Row Lock + Deterministic Idempotency Guard",
                    "design": "Acquire `SELECT ... FOR UPDATE NOWAIT` on the target aggregate row inside one database transaction and reject concurrent duplicate mutations with HTTP 409 Conflict.",
                },
                "option_b": {
                    "label": "Idempotency-Key Ledger + Optimistic Version CAS",
                    "design": "Require an `Idempotency-Key` request header persisted in a unique key table and enforce `UPDATE ... SET version = version + 1 WHERE id = :id AND version = :expected`.",
                },
            },
            "pm_tradeoff": (
                "Option A blocks simultaneous double-clicks immediately with a clear conflict toast and zero extra schema tables (fastest to ship). "
                "Option B transparently replays receipts across flaky mobile retries (+1 idempotency table)."
            ),
            "resolution": {"selected": "option_a"},
        },
        {
            "id": "MP-002",
            "title": "Split-Brain State Across Persistence and Side-Effects",
            "exploit_class": "partial_mutation",
            "spec_quote": sentences[min(1, len(sentences) - 1)],
            "monkeys_paw_grant": (
                "Agent executes database writes and downstream notifications/API calls sequentially inside the request handler; "
                "a mid-flight timeout leaves primary records committed while side-effects silently drop or double-fire on retry."
            ),
            "repo_citations": _cits_slice(1),
            "eng_options": {
                "option_a": {
                    "label": "Transactional Outbox Event + Idempotent Consumer",
                    "design": "Commit domain state change and an `outbox_events` (`status='PENDING'`) record in the same SQL transaction, dispatching external calls asynchronously with deterministic keys.",
                },
                "option_b": {
                    "label": "Two-Phase Explicit `PENDING_SYNC` State Machine",
                    "design": "Persist record in `PENDING_SYNC` status first, invoke downstream dependency synchronously with bounded 5s timeout, and transition to `ACTIVE` or `FAILED_RETRYABLE`.",
                },
            },
            "pm_tradeoff": (
                "Option A guarantees zero split-brain data loss and sub-100ms UI response with eventual async delivery. "
                "Option B confirms external completion inline while the user waits (~1-3s spinner)."
            ),
            "resolution": {"selected": "option_a"},
        },
        {
            "id": "MP-003",
            "title": "Missing Tenant Ownership & Role Ceiling Enforcement",
            "exploit_class": "auth_boundary_leak",
            "spec_quote": sentences[min(2, len(sentences) - 1)],
            "monkeys_paw_grant": (
                "Agent verifies only that a caller is logged in (`is_authenticated`) and queries records by primary ID alone, "
                "allowing cross-tenant IDOR access or low-privilege members to trigger privileged mutations."
            ),
            "repo_citations": _cits_slice(2),
            "eng_options": {
                "option_a": {
                    "label": "Tenant-Scoped Predicate + Explicit RBAC Role Gate",
                    "design": "Constrain all lookups by `(id = :target_id AND tenant_id = :caller.tenant_id)` (returning HTTP 404 on mismatch) and require explicit authorized role membership with audit log entries.",
                },
                "option_b": {
                    "label": "Tenant Scoping + Threshold Approval Workflow",
                    "design": "Enforce strict tenant query scoping plus a staged `PENDING_APPROVAL` workflow whenever standard operators initiate high-impact mutations.",
                },
            },
            "pm_tradeoff": (
                "Option A locks down cross-tenant leaks and role boundaries immediately for v1 launch. "
                "Option B adds a manager approval queue UI (+2-3 days scope)."
            ),
            "resolution": {"selected": "option_a"},
        },
    ]

    if has_batch or len(sentences) >= 4:
        findings.append(
            {
                "id": "MP-004",
                "title": "Orphaned Background Schedules & Unbounded Batch Loops",
                "exploit_class": "blast_radius_scale" if has_batch else "orphaned_state",
                "spec_quote": sentences[min(3, len(sentences) - 1)],
                "monkeys_paw_grant": (
                    "Agent processes unbounded record sets synchronously in one HTTP request or mutates parent lifecycle state "
                    "while leaving queued scheduled jobs and cached entitlements active."
                ),
                "repo_citations": _cits_slice(3),
                "eng_options": {
                    "option_a": {
                        "label": "Bounded Page Size Cap + Execution-Time Lifecycle Guard",
                        "design": "Enforce strict page/batch upper bound (`<= 100` items per call, HTTP 413 above cap) and re-verify parent active status inside worker execution.",
                    },
                    "option_b": {
                        "label": "Chunked Cursor Background Job + Explicit Schedule Cancel",
                        "design": "Enqueue cursor-paginated chunks (`100` items/chunk) via `FOR UPDATE SKIP LOCKED` worker pool and atomically cancel pending child schedules on parent state change.",
                    },
                },
                "pm_tradeoff": (
                    "Option A protects server stability immediately with predictable limits. "
                    "Option B supports 10,000+ item operations with background progress tracking (+1 status endpoint)."
                ),
                "resolution": {"selected": "option_a"},
            }
        )

    return {
        "schema_version": "1.0",
        "mode": mode,
        "draft_title": title,
        "findings": findings,
    }


def _build_deterministic_backlog(
    prd_text: str,
    findings_doc: dict[str, Any],
    preset: str,
) -> list[dict[str, Any]]:
    """Synthesize a clean, editable hierarchy tree inheriting locked Monkey's Paw EARS guardrails."""
    title = infer_title(prd_text, findings_doc, fallback_name="Core Product Initiative")
    raw_findings = findings_doc.get("findings") or []
    resolved = [resolve_finding_choice(f) for f in raw_findings]
    levels = get_preset_levels(preset)

    # Group resolved guardrails into logical functional slices
    core_guards = [r for r in resolved if r["exploit_class"] in {"concurrency_race", "partial_mutation"}]
    sec_guards = [r for r in resolved if r["exploit_class"] not in {"concurrency_race", "partial_mutation"}]
    if not core_guards:
        core_guards = resolved[:2]
    if not sec_guards:
        sec_guards = resolved[2:]

    def _make_stories(group: list[dict[str, Any]], domain_focus: str) -> list[dict[str, Any]]:
        if not group:
            return [
                {
                    "level": "story",
                    "title": f"Implement {domain_focus} happy-path & validation contract",
                    "description": f"As a product user, I want {domain_focus.lower()} to execute deterministically, so that outcomes match expected acceptance criteria.",
                    "estimate": "3",
                    "acceptance_criteria": [
                        f"WHEN a user triggers {domain_focus.lower()}, THE SYSTEM SHALL persist state atomically and return deterministic confirmation."
                    ],
                    "guardrail_ids": [],
                    "repo_touchpoints": [],
                }
            ]
        stories: list[dict[str, Any]] = []
        for item in group:
            stories.append(
                {
                    "level": "story",
                    "title": f"{item['title']} — {item['chosen_tag']}",
                    "description": (
                        f"As an engineering & product stakeholder, I want to enforce {item['chosen_tag']} "
                        f"so that we prevent '{item['exploit_class']}' loopholes while preserving: {item['pm_tradeoff']}"
                    ),
                    "estimate": "5" if "Option B" in item["chosen_tag"] else "3",
                    "acceptance_criteria": list(item["ears_clauses"]),
                    "guardrail_ids": [item["id"]],
                    "repo_touchpoints": list(item["citations"]),
                }
            )
        return stories

    feat_core = {
        "level": "feature",
        "title": f"{title}: Atomic State Transitions & Idempotency",
        "description": "Core transactional workflow, concurrency locking, and external side-effect coordination.",
        "estimate": "8",
        "acceptance_criteria": [
            c for r in core_guards for c in r["ears_clauses"][:1]
        ]
        or ["WHEN core workflow executes, THE SYSTEM SHALL commit state atomically."],
        "guardrail_ids": [r["id"] for r in core_guards],
        "repo_touchpoints": [cit for r in core_guards for cit in r["citations"]],
        "children": _make_stories(core_guards, "Core Transactional Workflow"),
    }

    feat_sec = {
        "level": "feature",
        "title": f"{title}: Access Boundaries, Lifecycle Cleanup & Scale Guards",
        "description": "Tenant/RBAC enforcement, lifecycle cleanup of dependent jobs/caches, and bounded execution.",
        "estimate": "5",
        "acceptance_criteria": [
            c for r in sec_guards for c in r["ears_clauses"][:1]
        ]
        or ["WHEN unauthorized or out-of-bounds input arrives, THE SYSTEM SHALL fail closed."],
        "guardrail_ids": [r["id"] for r in sec_guards],
        "repo_touchpoints": [cit for r in sec_guards for cit in r["citations"]],
        "children": _make_stories(sec_guards, "Authorization & Lifecycle Guardrails"),
    }

    all_ids = [r["id"] for r in resolved]
    all_cits: list[str] = []
    for r in resolved:
        for c in r["citations"]:
            if c not in all_cits:
                all_cits.append(c)

    if levels == ["epic", "feature", "story"]:
        raw_tree = [
            {
                "level": "epic",
                "title": title,
                "description": prd_text.strip()[:400],
                "estimate": "13",
                "acceptance_criteria": [
                    f"All {len(resolved)} refereed Monkey's Paw guardrails ({', '.join(all_ids)}) verified in automated tests."
                ],
                "guardrail_ids": all_ids,
                "repo_touchpoints": all_cits[:6],
                "children": [feat_core, feat_sec],
            }
        ]
    elif levels == ["capability", "epic", "feature", "story"]:
        raw_tree = [
            {
                "level": "capability",
                "title": f"{title} Platform Capability",
                "description": f"End-to-end organizational capability governing: {title}.",
                "estimate": "13",
                "acceptance_criteria": [
                    "Capability satisfies locked EARS concurrency, security, and operational guardrails."
                ],
                "guardrail_ids": all_ids,
                "repo_touchpoints": all_cits[:6],
                "children": [
                    {
                        "level": "epic",
                        "title": f"{title} — v1 Production Delivery",
                        "description": prd_text.strip()[:400],
                        "estimate": "13",
                        "acceptance_criteria": [
                            f"Zero unresolved malicious-compliance findings across {', '.join(all_ids)}."
                        ],
                        "guardrail_ids": all_ids,
                        "repo_touchpoints": all_cits[:6],
                        "children": [feat_core, feat_sec],
                    }
                ],
            }
        ]
    else:
        # Default `enterprise_4tier`: Epic -> Capability -> Feature -> Story
        raw_tree = [
            {
                "level": "epic",
                "title": title,
                "description": prd_text.strip()[:400],
                "estimate": "13",
                "acceptance_criteria": [
                    f"All {len(resolved)} Monkey's Paw production guardrails ({', '.join(all_ids)}) locked and verified."
                ],
                "guardrail_ids": all_ids,
                "repo_touchpoints": all_cits[:6],
                "children": [
                    {
                        "level": "capability",
                        "title": "Transactional Execution & Reliability",
                        "description": "Guarantees idempotent state transitions and split-brain recovery.",
                        "estimate": "8",
                        "acceptance_criteria": feat_core["acceptance_criteria"],
                        "guardrail_ids": feat_core["guardrail_ids"],
                        "repo_touchpoints": feat_core["repo_touchpoints"],
                        "children": [feat_core],
                    },
                    {
                        "level": "capability",
                        "title": "Tenant Governance, Lifecycle & Scale Protection",
                        "description": "Enforces authorization ceilings, dependent job cleanup, and bounded load.",
                        "estimate": "5",
                        "acceptance_criteria": feat_sec["acceptance_criteria"],
                        "guardrail_ids": feat_sec["guardrail_ids"],
                        "repo_touchpoints": feat_sec["repo_touchpoints"],
                        "children": [feat_sec],
                    },
                ],
            }
        ]

    return normalize_backlog_tree(raw_tree, preset=preset)


# ---------------------------------------------------------------------------
# Public Engine Entrypoints (LLM + Validator Self-Healing)
# ---------------------------------------------------------------------------


FINDINGS_SYSTEM_PROMPT = """You are Monkey's Paw + Staff TPM Referee: a pre-code malicious compliance referee.
Analyze the user's draft PRD/ticket alongside the repository surface JSON.
Expose the top 3 to 5 ways a literal-minded, lazy coding agent could satisfy the literal words of the draft while breaking production.

STRICT JSON CONTRACT:
Return a single JSON object:
{
  "schema_version": "1.0",
  "mode": "<copy exact 'mode' from surface JSON: 'brownfield' or 'greenfield'>",
  "draft_title": "<concise title>",
  "findings": [
    {
      "id": "MP-001",
      "title": "<short concrete exploit title>",
      "exploit_class": "<MUST be one of: orphaned_state, partial_mutation, auth_boundary_leak, concurrency_race, blast_radius_scale, silent_fallback>",
      "spec_quote": "<exact quote or explicit <OMISSION: ...> from PRD (>= 10 chars)>",
      "monkeys_paw_grant": "<concrete scenario showing how a literal agent breaks production (>= 25 chars)>",
      "repo_citations": ["<non-empty file:line paths from surface JSON when mode=='brownfield'; [] when mode=='greenfield'>"],
      "eng_options": {
        "option_a": {"label": "<short lean design name>", "design": "<concrete mechanism naming locks, tables, HTTP status codes, or queues>"},
        "option_b": {"label": "<short durable/scale design name>", "design": "<distinct concrete engineering alternative>"}
      },
      "pm_tradeoff": "<plain-English UX, latency, and timeline trade-off for Product Owners without internal DB jargon>",
      "resolution": {
        "selected": "option_a",
        "ears_clauses": ["WHEN <trigger>, THE SYSTEM SHALL <verifiable requirement>."]
      }
    }
  ]
}

ANTI-SLOP RULES (enforced by deterministic validator):
- NEVER write generic filler ('add proper error handling', 'implement robust validation', 'follow best practices', 'handle edge cases gracefully').
- Cap findings strictly between 1 and 5.
- When mode is 'brownfield', repo_citations MUST cite real files from the provided surface JSON.
"""


BACKLOG_SYSTEM_PROMPT = """You are a Principal Technical Program Manager & Systems Architect.
Given a PRD, locked Monkey's Paw architectural resolutions, and a requested Agile hierarchy preset, decompose the work into a crisp, actionable, inline-editable backlog tree.

Every locked Monkey's Paw guardrail (MP-001, etc.) MUST flow into the Acceptance Criteria (`WHEN ... THE SYSTEM SHALL ...`) and `guardrail_ids` of the Features and User Stories that implement it.

Return a single JSON object:
{
  "tree": [
    {
      "level": "<top level of preset>",
      "title": "...",
      "description": "...",
      "estimate": "13",
      "acceptance_criteria": ["..."],
      "guardrail_ids": ["MP-001"],
      "repo_touchpoints": ["path/file.py:42"],
      "children": [ ... nested down to 'story' level where description uses 'As a <role>, I want <action>, so that <value>' ... ]
    }
  ]
}
"""


def generate_validated_findings(
    prd_text: str,
    surface_payload: dict[str, Any],
    provider_cfg: dict[str, str],
) -> tuple[dict[str, Any], str]:
    """Generate 1..5 validated Monkey's Paw findings and return `(findings_doc, engine_used_label)`."""
    if provider_cfg["provider"] == "demo":
        doc = _build_deterministic_findings(prd_text, surface_payload)
        ok, errors, _ = validate_findings_data(doc, surface_data=surface_payload)
        if not ok:
            raise RuntimeError(f"Internal sandbox validation error: {errors}")
        return doc, "demo (deterministic sandbox)"

    mode = surface_payload.get("mode", "greenfield")
    compact_surface = json.dumps(surface_payload, separators=(",", ":"))[:28_000]
    user_prompt = (
        f"REPOSITORY MODE: {mode}\n"
        f"ALLOWED EXPLOIT CLASSES: {sorted(VALID_EXPLOIT_CLASSES)}\n\n"
        f"REPOSITORY SURFACE JSON:\n{compact_surface}\n\n"
        f"DRAFT PRD / ACCEPTANCE CRITERIA:\n{prd_text[:18_000]}"
    )

    candidate = _call_llm_json(FINDINGS_SYSTEM_PROMPT, user_prompt, provider_cfg)
    # Default pre-selection to option_a if model omitted resolution so UI starts ready to tweak or lock
    if isinstance(candidate, dict) and isinstance(candidate.get("findings"), list):
        candidate["mode"] = mode
        for f in candidate["findings"]:
            if isinstance(f, dict) and "resolution" not in f:
                f["resolution"] = {"selected": "option_a"}

    ok, errors, _ = validate_findings_data(candidate, surface_data=surface_payload)
    if ok:
        return candidate, f"{provider_cfg['provider']}:{provider_cfg['model']}"

    # 1 automatic self-healing pass feeding exact validator errors back to the model
    repair_prompt = (
        f"{user_prompt}\n\n"
        f"YOUR PREVIOUS JSON FAILED DETERMINISTIC VALIDATION WITH THESE EXACT ERRORS:\n"
        + "\n".join(f"- {e}" for e in errors)
        + "\n\nFix every error above and return the corrected JSON object."
    )
    repaired = _call_llm_json(FINDINGS_SYSTEM_PROMPT, repair_prompt, provider_cfg)
    if isinstance(repaired, dict) and isinstance(repaired.get("findings"), list):
        repaired["mode"] = mode
        for f in repaired["findings"]:
            if isinstance(f, dict) and "resolution" not in f:
                f["resolution"] = {"selected": "option_a"}

    ok2, errors2, _ = validate_findings_data(repaired, surface_data=surface_payload)
    if not ok2:
        raise ValueError("LLM output failed Monkey's Paw validation after repair: " + "; ".join(errors2))
    return repaired, f"{provider_cfg['provider']}:{provider_cfg['model']} (self-healed)"


def generate_editable_backlog(
    prd_text: str,
    findings_doc: dict[str, Any],
    preset: str,
    provider_cfg: dict[str, str],
) -> tuple[list[dict[str, Any]], str]:
    """Generate an inline-editable Epic/Capability/Feature/User Story backlog tree."""
    ok, errors, _ = validate_findings_data(findings_doc, require_resolved=True)
    if not ok:
        raise ValueError("Lock all Decision Cards before generating the work breakdown: " + "; ".join(errors))

    if provider_cfg["provider"] == "demo":
        return _build_deterministic_backlog(prd_text, findings_doc, preset), "demo (deterministic sandbox)"

    levels = get_preset_levels(preset)
    resolved_summary = [resolve_finding_choice(f) for f in findings_doc.get("findings", [])]
    user_prompt = (
        f"HIERARCHY LEVELS (top to bottom): {' -> '.join(levels)}\n\n"
        f"ORIGINAL PRD:\n{prd_text[:14_000]}\n\n"
        f"LOCKED MONKEY'S PAW DECISIONS (MUST BE WOVEN INTO FEATURE/STORY ACCEPTANCE CRITERIA):\n"
        f"{json.dumps(resolved_summary, indent=2)}"
    )

    resp = _call_llm_json(BACKLOG_SYSTEM_PROMPT, user_prompt, provider_cfg)
    raw_tree = resp.get("tree") if isinstance(resp, dict) else resp
    normalized = normalize_backlog_tree(raw_tree, preset=preset)
    if not normalized:
        normalized = _build_deterministic_backlog(prd_text, findings_doc, preset)
    return normalized, f"{provider_cfg['provider']}:{provider_cfg['model']}"
