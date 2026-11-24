# Monkey's Paw User Guide (`v1.1`)

Welcome to **Monkey's Paw** — a pre-code specification referee and Agile work-breakdown workbench built for **Product Owners, Technical Program Managers (TPMs), and Software Engineers**.

Monkey's Paw catches the hidden production loopholes in PRDs, epics, and tickets *before* any application code gets written, translates engineering trade-offs into plain English for Product, and compiles locked decisions into **editable Epics, Capabilities, Features, User Stories, Jira CSV imports, and EARS/Spec-Kit specifications**.

---

## 1. Choose How You Want to Run Monkey's Paw

Monkey's Paw runs in two ways that share the exact same core validation engine:

| Mode | Best For | Requirements |
| :--- | :--- | :--- |
| **A. Monkey's Paw Studio (Web App)** | **PMs, Product Owners, TPMs, & Tech Leads** refining PRDs, inspecting GitHub repos, editing Epic/Capability/Feature/Story hierarchies, and exporting to Jira. | Python 3.10+ locally (`python3 -m studio`) **or** 1-click container deploy on **Railway**. |
| **B. Portable Agent Skill (`SKILL.md` + MCP)** | **Engineers** working directly inside Antigravity, Claude Code, Cursor, Codex, GitHub Copilot, Windsurf, Kiro, or Gemini CLI. | Python 3.10+ (`npx skills add orphik/monkey-paw` or `git clone`). |

Both modes use **Python 3.10+ standard library only** — zero `pip install` packages required.

---

## 2. Running Monkey's Paw Studio Locally (30 Seconds)

From the `monkey-paw` repository root:

```bash
python3 -m studio --port 8787
```
*(On Windows where `python` is your Python 3.10+ binary, run `python -m studio --port 8787`.)*

Open **http://localhost:8787** in your browser.

- **Works immediately with zero API keys:** Out of the box, Studio includes a **Deterministic Sandbox** engine so you can test-drive PRD ingestion, GitHub/local repo scanning, Decision Cards, Backlog editing, and Jira CSV exports offline.
- **1-Click GUI Environment Setup (`Setup Env Vars`):** On `localhost`, click the green **Setup Env Vars** button in the top header bar to paste `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, or `STUDIO_PASSCODE` directly into your local gitignored `.env` file with zero server restart. On Railway, **Setup Env Vars** displays live masked server key status while keeping disk writes locked down.

---

## 3. Step-by-Step Studio Walkthrough (For PMs, TPMs & Engineers)

### Step 1: Ingest Your PRD & Repository Context
1. **Paste or upload your draft:** Paste a PRD, epic brief, or rough acceptance criteria into **1A** (or click `Upload .md/.txt`, or load one of the built-in sample PRDs).
2. **Choose your Repository Surface Mode (`1B`):**
   - **Greenfield — No Repository Yet:** Select this for brand-new products or concepts that do not have a codebase yet. Monkey's Paw focuses on domain state transitions, idempotency, and permission boundaries.
   - **GitHub Repository URL:** Enter `https://github.com/owner/repo` (or `owner/repo` shorthand) plus an optional branch. For private repositories, paste a read-only GitHub Personal Access Token (`GITHUB_TOKEN`) — Studio performs a shallow `--depth 1` scan in a temporary directory and **immediately deletes the clone** after extracting structural metadata.
   - **Local Repository Folder *(localhost only)*:** Point directly at a local folder such as `C:\MyProject` or `/Users/me/app`.
3. **Select your Agile Work Breakdown Hierarchy:**
   - **Enterprise 4-Tier:** `Epic -> Capability -> Feature -> User Story` (ideal for SAFe / Jira Align / enterprise portfolios)
   - **Capability-First:** `Capability -> Epic -> Feature -> User Story`
   - **Agile 3-Tier:** `Epic -> Feature -> User Story` (ideal for standard Jira / Linear teams)
4. Click **Run Monkey's Paw Analysis ->**.

---

### Step 2: Lock Bilingual Decision Cards & Park Tangents (<10 Minutes)
Studio generates **1 to 5 validated Bilingual Decision Cards** (gated by `scripts/validate_findings.py` so generic filler like *"add proper error handling"* is automatically blocked and self-healed):

- **Review the Exploit:** Each card quotes the exact ambiguous line in your PRD, explains how a literal coding agent would break production (**Monkey's Paw Exploit**), and cites the exact `file:line` touchpoints in your repo.
- **Pick Option A, Option B, or Custom:**
  - **Engineers** compare concrete Option A vs. Option B mechanics (row locks, outbox queues, tenant predicates, batch caps).
  - **Product Owners** read the purple **PM Trade-off** box showing plain-English customer UX, latency, and delivery timeline impact.
  - Need a hybrid rule? Click **Or Specify Custom Guardrail** and type your exact constraint.
- **Trap Scope Creep (`PARKING-LOT.md`):** When a teammate brings up a Phase-2 idea or unrelated tech debt during discussion, enter it in the **Tangent Trap** bar (`+ Park Tangent`). It gets logged as `PL-001`, `PL-002`, etc. without derailing v1 scope.
- Click **Generate Editable Work Breakdown ->**.

---

### Step 3: Edit Your Epics, Capabilities, Features & User Stories Inline
Studio transforms your PRD + locked Monkey's Paw decisions into a visual, color-coded hierarchy where **every locked guardrail (`MP-001`, `MP-002`, ...) automatically flows into the Acceptance Criteria of the Features and User Stories it governs**:

- **Edit any field inline:** Click any title, story point estimate, description (`As a <persona>, I want <goal>, so that <outcome>`), repo touchpoint list, or Acceptance Criterion line to edit it directly. Changes auto-save to SQLite and browser backup.
- **Reshape the tree freely:**
  - Click **`+ capability` / `+ feature` / `+ story`** on any item to add a child work item.
  - Click **`+ Add Criterion`** to add EARS (`WHEN ... THE SYSTEM SHALL ...`) or `GIVEN / WHEN / THEN` criteria.
  - Use **`↑` / `↓`** to reorder items, **`Delete`** to prune items, or switch the **Hierarchy Preset** dropdown at the top to re-index IDs (`EPIC-1`, `CAP-1.1`, `FEAT-1.1.1`, `US-1.1.1.1`) automatically.

---

### Step 4: Share & Export to Jira, Spec-Kit, OpenSpec, or EARS
1. **Share a live link:** Click **Share Link** in the top bar to copy `/s/s_<unguessable_id>` and send it to a teammate on your Studio instance, or download the **Session JSON** bundle to share offline.
2. **Export into your tools:**
   - **`Jira CSV (.csv)`:** Formatted for **Jira -> Settings -> System -> External System Import -> CSV**. Map `Issue ID` -> Issue Id, `Parent ID` -> Parent Id, `Issue Type` -> Issue Type, `Summary` -> Summary, `Description` -> Description, and `Story Points` -> Story Points to create the entire linked hierarchy in one import.
   - **`BACKLOG.md`:** Executive-ready work breakdown document with checkboxes, estimates, guardrail tags, and parked items.
   - **`SPEC.md (EARS)` / `Spec-Kit` / `OpenSpec` / `Jira Checklist`:** Ready to drop directly into your repository so coding agents implement the exact locked specification on the first pass.

---

## 4. Deploying Monkey's Paw Studio on Railway

`monkey-paw` includes a turnkey non-root [`Dockerfile`](../Dockerfile) and [`railway.json`](../railway.json) with `/api/health` readiness probes.

### Deploy Steps
1. In [Railway](https://railway.com), click **New Project -> Deploy from GitHub repo** and select `orphik/monkey-paw` (or run `railway up` via the Railway CLI).
2. *(Optional — Persistent Shared Links Across Redeploys):* Right-click your Railway service -> **Attach Volume** -> mount path **`/data`**. Studio automatically stores `monkey_paw_studio.sqlite3` on `/data` when writable.
3. Configure **Variables** on your Railway service:

| Environment Variable | Required? | Purpose |
| :--- | :--- | :--- |
| `STUDIO_PASSCODE` | **Recommended** | Protects your hosted Studio behind a constant-time passcode prompt whenever you attach server-side LLM or GitHub keys. |
| `GEMINI_API_KEY` | Optional | Enables server-side Google Gemini analysis (`gemini-3.8-flash` default). |
| `ANTHROPIC_API_KEY` | Optional | Enables server-side Anthropic Claude analysis (`claude-sonnet-4-20250514` default). |
| `OPENAI_API_KEY` | Optional | Enables server-side OpenAI analysis (`gpt-4.1-mini` default). |
| `OPENAI_COMPAT_BASE_URL` | Optional | Base URL for OpenRouter, vLLM, or Ollama (`OPENAI_COMPAT_API_KEY` optional). |
| `STUDIO_DEFAULT_MODEL` | Optional | Override default model name for the active server provider. |
| `GITHUB_TOKEN` | Optional | Fine-grained read-only `Contents: Read` token if your team scans private org repos by default. |
| `STUDIO_DB_PATH` | Optional | Custom SQLite path (auto-detects `/data/monkey_paw_studio.sqlite3` on Railway or `.monkey-paw/studio.sqlite3` locally). |

4. Under **Settings -> Networking**, click **Generate Domain** to get your public HTTPS Studio URL.

> **Hosted Security Default:** Whenever `RAILWAY_ENVIRONMENT` is present (or `--host 0.0.0.0` is used), local filesystem path scanning (`local_path`) is **automatically disabled** so remote users can only scan `https://github.com/...` repositories or run in Greenfield mode.

---

## 5. Using the CLI & IDE Agent Skill (`SKILL.md`)

Engineers working inside an AI IDE can also install the skill directly without running the web server:

```bash
# Via Agent Skills CLI:
npx skills add orphik/monkey-paw

# Or via pure Git (no Node.js needed):
git clone https://github.com/orphik/monkey-paw.git ~/.gemini/config/skills/monkey-paw
```

Then ask your coding agent in natural language before starting any feature:
> *"Stress-test `prd.md` against this repo for loopholes and deal me A/B decision cards before writing code."*

---

## 6. Security & Privacy Summary

- **Read-Only Source Guarantee:** Monkey's Paw never edits application source code.
- **Ephemeral GitHub Clones:** Remote repo scans use `--depth 1 --filter=blob:limit=524288` into an isolated temp folder that is wiped immediately in a `finally` block.
- **Two-Layer Secret Shield:** `.env*`, `*.pem`, `*.key`, `id_rsa*`, `*credentials*.json`, `.npmrc`, and `.netrc` are blocked before opening, and any inline token patterns (`sk-...`, `AKIA...`, `ghp_...`, private keys, credentialed URLs) are scrubbed prior to emitting `surface.json`.
- **Credential-Free Database:** Browser BYOK keys and session GitHub PATs are stripped before SQLite saves and live only in browser `sessionStorage`.
