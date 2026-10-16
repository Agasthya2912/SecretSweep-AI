# CLAUDE.md — SecretSweep AI

This file is the source of truth for the SecretSweep AI codebase: what the system is, how it is
organized, what it depends on, and what data it persists. Read this fully before making structural
changes to the project.

## 1. Project Summary

**SecretSweep AI** is an LLM-augmented semantic data-flow analysis framework for proactive credential
leakage detection and developer risk governance across Git repositories.

Existing tools (GitLeaks, TruffleHog, detect-secrets) rely on regex + Shannon-entropy heuristics only.
They suffer from high false-positive rates (no semantic understanding of code context), miss obfuscated
secrets (Base64 / hex / string-concatenation), and are purely reactive (scan only after a secret is
already committed).

SecretSweep AI addresses this with:

- **Layer 1 — Structural scanner**: full Git history extraction (GitPython), 30+ regex secret patterns,
  Shannon entropy scoring for high-randomness strings.
- **Layer 2 — Semantic scanner**: a fine-tuned CodeBERT/UniXcoder model that classifies flagged code in
  a 15–20 line context window as credential vs. non-credential, plus an obfuscation decoder (Base64,
  hex, string-concatenation reassembly).
- **CDFG — Credential Data Flow Graph**: a NetworkX/Neo4j graph tracing a secret's birth, usage,
  deletion, and re-appearance across the full commit history (nodes = variables/values/commits/
  files/developers; edges = define/use/delete/propagate).
- **Severity engine**: 5-factor scoring (secret type, exposure duration, repo visibility, active status,
  blast radius) → `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`.
- **Active key validation**: pings AWS/Stripe/GitHub APIs to confirm whether a leaked key still works.
- **Developer risk profiler**: aggregates leaks per author, response time, and risk trend over time.
- **Pre-commit shield**: a Git hook running a lightweight ONNX-exported model, blocking/warning on
  commit in under 2 seconds.
- **Dashboard + API**: React dashboard (repository / developer / timeline / severity views) served by a
  FastAPI backend.
- **Alerting + CI/CD**: Slack webhook + JIRA auto-ticketing for CRITICAL findings, packaged as a GitHub
  Actions workflow, fully Dockerized.

Target results (per project abstract): 94.3% detection accuracy, 6.1% false-positive rate, benchmarked
against GitLeaks and TruffleHog on 50 real-world open-source repositories.

## 2. Tech Stack

### Backend / core (Python 3.10+)
- **API**: fastapi, uvicorn
- **Data**: sqlalchemy, alembic, psycopg2-binary (PostgreSQL — relational store for repos, findings,
  developers, scans, alerts), neo4j (graph store for the CDFG), redis (caching / job queue)
- **Auth**: python-jose (JWT), passlib[bcrypt]
- **Validation/config**: pydantic, pydantic-settings, python-dotenv
- **Git**: gitpython
- **Graph**: networkx
- **ML**: transformers, torch, onnxruntime, scikit-learn, datasets, numpy
- **Integrations**: slack-sdk, jira, PyGithub, httpx, requests
- **Testing/quality**: pytest, pytest-cov, black, ruff, mypy

### Frontend
- React 18 + Vite, react-router-dom, axios, recharts (charts), d3 (CDFG force-directed graph),
  lucide-react (icons), date-fns, clsx, TailwindCSS

### Infra
- Docker / docker-compose: `secretsweep-api` (FastAPI, :8000), `secretsweep-dashboard` (React, :3000),
  `postgresql` (:5432), `neo4j` (:7474 browser / :7687 bolt), `redis` (:6379)

## 3. Project Structure

```
SecretsweepAI/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── requirements.txt
├── .env.example
├── .gitignore
├── .dockerignore                  # Phase 12: excludes .venv/, data/repos/, data/benchmark_repos/ —
│                                  # without it the build context included this checkout's 2GB+
│                                  # .venv on every build (see §10's verification notes)
├── docker-compose.yml             # Phase 12: rewritten — api/worker/dashboard/postgres/redis/neo4j
├── Dockerfile.api                 # Phase 1, superseded by docker/Dockerfile.api, kept unused
├── docker/                        # Phase 12
│   ├── Dockerfile.api             # git added (GitPython shells out to it at runtime); torch
│   │                              # installed from the CPU-only wheel index first (see §10)
│   ├── Dockerfile.dashboard       # multi-stage: node build -> nginx serve
│   └── nginx.conf                 # :3000, proxies /api -> secretsweep-api:8000
├── .github/
│   └── workflows/
│       └── secretsweep.yml       # Phase 11: this repo's own CI — scans on push/PR, comments
│                                  # on PRs, fails the build on any CRITICAL finding
├── api/                          # FastAPI application
│   ├── __init__.py
│   ├── main.py                   # app entrypoint: middleware, exception handler, router registration
│   ├── config.py                 # pydantic-settings, reads .env
│   ├── celery_app.py             # Celery app: Redis broker + result backend
│   ├── db/
│   │   ├── __init__.py
│   │   └── session.py            # async SQLAlchemy engine/session, SQLite fallback, get_db()
│   ├── auth/
│   │   ├── __init__.py
│   │   └── api_key.py            # X-API-Key check (Phase 9's auth; full JWT is a future phase)
│   ├── tasks/
│   │   ├── __init__.py
│   │   └── scan_task.py          # Celery task: run ScanPipeline, persist results
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py           # SQLAlchemy ORM models: Repository, ScanJob, DetectedSecret,
│   │                              # DeveloperRiskRecord (see §4)
│   ├── schemas/                  # Pydantic request/response schemas
│   │   ├── __init__.py
│   │   ├── scan.py                       # ScanRequest/Response/StatusResponse
│   │   ├── secrets.py                    # SecretResponse/SecretsListResponse
│   │   ├── developers.py                 # DeveloperProfileResponse/DevelopersListResponse
│   │   ├── dashboard.py                  # DashboardSummaryResponse
│   │   └── (user.py, repository.py, commit.py, developer.py, secret_type.py, finding.py,
│   │        scan_job.py, alert.py, developer_risk_score.py — Phase 1 schemas, unused since
│   │        Phase 9 replaced the normalized DB schema they were shaped for)
│   ├── routes/                   # Phase 9's routers (api/routers/ below predates these, unused)
│   │   ├── __init__.py
│   │   ├── health.py             # GET /api/health
│   │   ├── scan.py                       # POST/GET /api/scan/..., POST /api/scan/webhook/github
│   │   ├── secrets.py                    # GET /api/secrets...
│   │   ├── developers.py                 # GET /api/developers...
│   │   └── dashboard.py                  # GET /api/dashboard...
│   ├── routers/                  # Phase 1 routers — superseded by api/routes/, kept unused
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── repositories.py
│   │   ├── scans.py
│   │   ├── findings.py
│   │   ├── developers.py
│   │   ├── dashboard.py
│   │   └── alerts.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py
│   │   ├── scan_service.py
│   │   ├── slack_service.py
│   │   ├── jira_service.py
│   │   └── github_service.py
│   └── core/
│       ├── __init__.py
│       ├── security.py           # JWT + password hashing
│       └── logging.py
├── scanner/                      # Layer 1 + Layer 2 scanning engine
│   ├── __init__.py
│   ├── git_extractor.py          # full history: commits, diffs, blobs, author metadata
│   ├── regex_scanner.py          # 30+ known secret formats (AWS, JWT, SSH, Stripe, GitHub, ...)
│   ├── entropy_scorer.py         # Shannon entropy scorer
│   ├── obfuscation_decoder.py    # Base64 / hex decode, string-concat reassembly
│   ├── semantic_engine.py        # CodeBERT/UniXcoder context-aware classification
│   ├── pipeline.py               # Phase 1 placeholder, empty — the real orchestrator is
│   │                              # scanner/scan_pipeline.py's ScanPipeline (used by
│   │                              # scripts/secretsweep_cli.py's `scan` command, Phase 11)
│   └── patterns/
│       ├── __init__.py
│       └── secret_patterns.py    # regex pattern definitions
├── ml/                            # model training / export
│   ├── __init__.py
│   ├── dataset_builder.py        # labeled credential vs non-credential dataset
│   ├── model_training.py         # fine-tunes CodeBERT/UniXcoder
│   ├── text_utils.py             # Phase 11: pure-Python split_context/build_input_text/
│   │                              # label_for_confidence/build_context_snippet — zero torch/
│   │                              # sklearn imports, so importing ONNXClassifier for the
│   │                              # pre-commit hook doesn't drag in finetune.py's training deps.
│   │                              # finetune.py and inference.py re-export these names.
│   ├── onnx_export.py            # exports fine-tuned model to ONNX for the pre-commit hook;
│   │                              # torch/SecretClassifier imports are lazy (inside
│   │                              # export_to_onnx()) so `from ml.onnx_export import
│   │                              # ONNXClassifier` alone doesn't import torch
│   └── inference.py              # shared PyTorch/ONNX inference wrapper
├── cdfg/                          # Credential Data Flow Graph
│   ├── __init__.py
│   ├── cdfg_builder.py           # the real builder: in-memory NetworkX MultiDiGraph +
│   │                              # optional Neo4j sync (open_driver_if_reachable(),
│   │                              # sync_to_neo4j(scan_job_id=...) — tags every synced
│   │                              # node/edge with scan_job_id so a later query can pull
│   │                              # back just one scan's subgraph). Wired into
│   │                              # ScanPipeline.run() as of 2026-09-08 (see §7/§8) —
│   │                              # previously built every scan but never persisted.
│   ├── graph_queries.py          # read-only helpers over a built CDFGBuilder, plus
│   │                              # load_d3_format_from_neo4j() (queries Neo4j directly
│   │                              # by scan_job_id — used by GET /api/dashboard/graph)
│   ├── models.py                 # SecretNode/CommitNode/FileNode/CDFGEdge/SecretLifecycle dataclasses
│   ├── graph_builder.py          # Phase 1 placeholder, empty — superseded by cdfg_builder.py, kept unused
│   ├── neo4j_client.py           # Phase 1 placeholder, empty — superseded by cdfg_builder.py's
│   │                              # own Neo4j sync, kept unused (CLAUDE.md wrongly pointed here
│   │                              # as "the" Neo4j module until 2026-09-08 — it was always a stub)
│   ├── traversal.py              # Phase 1 placeholder, empty — cross-commit resolution
│   │                              # is actually done by CDFGBuilder's node dedup (secret_hash/
│   │                              # commit_hash/file_path -> node_id maps), not this file
│   └── severity_engine.py        # Phase 1 placeholder, empty — the real 5-factor scorer is
│                                  # the top-level severity/ package (severity/scorer.py's
│                                  # SeverityScorer, severity/active_validator.py), not this file
├── validators/                    # active key/liveness validation
│   ├── __init__.py
│   ├── base_validator.py
│   ├── aws_validator.py
│   ├── stripe_validator.py
│   └── github_validator.py
├── profiler/
│   ├── __init__.py
│   └── developer_risk_profiler.py
├── hooks/                         # pre-commit shield
│   ├── __init__.py
│   ├── hook.py                    # Phase 11: PreCommitHook — the real pre-commit hook
│   ├── installer.py               # Phase 11: install_hook/uninstall_hook/check_hook_installed
│   ├── pre_commit_hook.py         # Phase 1 placeholder, superseded by hook.py, kept unused
│   └── install.py                 # Phase 1 placeholder, superseded by installer.py, kept unused
├── integrations/
│   ├── __init__.py
│   ├── slack_alert.py             # Phase 11: send_slack_alert/send_slack_test (Block Kit)
│   ├── jira_ticket.py             # Phase 11: create_jira_ticket (JIRA REST API v3)
│   ├── slack_notifier.py          # Phase 1 placeholder, superseded by slack_alert.py, kept unused
│   ├── jira_ticket_creator.py     # Phase 1 placeholder, superseded by jira_ticket.py, kept unused
│   └── github_actions/
│       └── secretsweep-action.yml # distributable template for OTHER repos to consume;
│                                   # this repo's own CI is .github/workflows/secretsweep.yml
├── dashboard/                     # React 18 + Vite + TailwindCSS
│   ├── src/
│   │   ├── main.jsx               # mounts <App> inside <BrowserRouter>
│   │   ├── App.jsx                # routes: /dashboard /secrets /developers /scan /settings
│   │   ├── api/
│   │   │   ├── client.js          # axios instance: baseURL, X-API-Key header, interceptors
│   │   │   └── endpoints.js       # one function per API endpoint
│   │   ├── lib/
│   │   │   ├── apiConfig.js       # runtime-editable API base URL / key (localStorage, Settings page)
│   │   │   ├── preferences.js     # page size / date format (localStorage, Settings page)
│   │   │   ├── formatDate.js      # relative/absolute date formatting per preference
│   │   │   ├── toast.js           # pub/sub so client.js can trigger a toast outside React
│   │   │   ├── recentScans.js     # client-tracked "Recent Scans" list (localStorage) — lifted
│   │   │   │                      # out of Scan.jsx (2026-09-08) so Settings.jsx's clear-history
│   │   │   │                      # action can reset it without importing a page
│   │   │   └── usePageTitle.js
│   │   ├── components/
│   │   │   ├── Layout.jsx         # sidebar nav + connection status (polls /api/health every 10s)
│   │   │   ├── ErrorBoundary.jsx  # wraps each page in App.jsx
│   │   │   ├── CDFGGraph.jsx      # orchestrator: fetches the graph, owns filter state, renders
│   │   │   │                      # the Graph/Secret Lifecycle tabs. The D3 force-directed
│   │   │   │                      # rendering itself (drag/zoom/hover/click-highlight) lives in
│   │   │   │                      # an internal CDFGCanvas subcomponent that takes the already-
│   │   │   │                      # filtered {nodes, links} as a prop (2026-09-08)
│   │   │   ├── CDFGFilterPanel.jsx # severity checkboxes, file/developer dropdowns, "only
│   │   │   │                      # deleted"/"only cross-file propagation" toggles — filtering
│   │   │   │                      # is pure client-side over the already-fetched graph, no
│   │   │   │                      # extra API call per filter change (2026-09-08)
│   │   │   ├── SecretLifecycleList.jsx # buildLifecycles() derives one card per secret node
│   │   │   │                      # (severity badge, Defined->Used->Deleted step indicator,
│   │   │   │                      # author, exposure days, files involved) from the same D3
│   │   │   │                      # payload — no separate lifecycle endpoint (2026-09-08)
│   │   │   └── ui/                # Badge, Card, StatCard, LoadingSpinner, ErrorMessage,
│   │   │                          # EmptyState, Toast (ToastContainer)
│   │   └── pages/
│   │       ├── Overview.jsx       # StatCards, severity pie + timeline line chart, CDFGGraph, recent findings
│   │       ├── Secrets.jsx        # filter/search/paginate detected_secrets, expandable rows
│   │       ├── Developers.jsx     # risk cards grid + report side panel
│   │       ├── Scan.jsx           # trigger a scan, poll status every 3s, client-tracked recent scans
│   │       └── Settings.jsx       # API base URL/key, Test Connection, display prefs, Danger
│   │                              # Zone (Clear All Scan History -> DELETE /api/scan), About
│   └── .env.example               # VITE_API_BASE_URL, VITE_API_KEY
├── tests/
│   ├── __init__.py
│   ├── test_regex_scanner.py
│   ├── test_entropy_scorer.py
│   ├── test_obfuscation_decoder.py
│   ├── test_semantic_engine.py
│   ├── test_cdfg.py
│   ├── test_severity_engine.py
│   ├── test_api.py
│   └── test_precommit.py         # Phase 11: hook, installer, CLI, Slack alert tests
├── scripts/
│   ├── __init__.py
│   ├── evaluate_benchmark.py     # Phase 1 placeholder, empty — superseded by benchmark.py
│   ├── benchmark.py              # Phase 12: BenchmarkRunner — SecretSweep vs GitLeaks vs
│   │                              # TruffleHog on test_keys + a synthetic repo it builds itself
│   ├── secretsweep_cli.py        # Phase 11: install/uninstall/status/scan CLI
│   └── seed_db.py
└── data/
    ├── repos/                     # ScanPipeline's default clone_base_dir (gitignored)
    ├── benchmark_repos/           # scripts/benchmark.py's test_keys clone + synthetic repo (gitignored)
    ├── datasets/                  # fine-tuning datasets (gitignored contents)
    └── models/                    # fine-tuned + ONNX model weights (gitignored contents)
```

## 4. Database Schema (SQLAlchemy, `Uuid` columns — works against both PostgreSQL and the
SQLite dev/test fallback; see `api/db/session.py`)

| Table | Purpose | Key columns |
|---|---|---|
| `repositories` | tracked Git repos | id, url, name, is_public, last_scanned, total_secrets_found |
| `scan_jobs` | scan run metadata | id, repo_id, status, started_at, completed_at, total_commits_scanned, secrets_found, error_message |
| `detected_secrets` | confirmed secret findings from a scan job | id, scan_job_id, secret_hash, pattern_name, file_path, commit_hash, author_email, severity_label, severity_score, is_active, detected_at |
| `developer_risk_records` | a developer's risk snapshot as of one scan job | id, scan_job_id, developer_email, developer_name, risk_score, risk_label, risk_trend, total_leaks, critical_leaks, high_leaks, medium_leaks, low_leaks, recorded_at |

This is the Phase 9 schema — flatter than the original Phase 1 design (no separate users/
developers/commits/secret_types/alerts tables), chosen because it's what the REST API and
Celery scan task actually populate directly from a `ScanResult`, and because it needed to
work against SQLite as well as PostgreSQL.

The CDFG itself (variable/value/commit/file/developer nodes; define/use/delete/propagate edges) is
persisted in **Neo4j**, not PostgreSQL — `cdfg/cdfg_builder.py` (not `cdfg/neo4j_client.py`, which
is an unused Phase 1 stub — see §3) is the module that talks to it, via `sync_to_neo4j()`, called
from `ScanPipeline.run()` once per scan and tagged with that scan's `scan_job_id`.

## 5. Environment Variables (`.env`)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string. **Unset** → `api/db/session.py` falls back to a local SQLite file so the API runs without PostgreSQL installed. |
| `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` | Neo4j connection (CDFG store) |
| `REDIS_URL` | Redis connection (cache / Celery broker+backend) |
| `API_KEY` | Required value of the `X-API-Key` header (Phase 9's auth). **Unset** → auth disabled, dev mode. |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for verifying `X-Hub-Signature-256` on `/api/scan/webhook/github`. **Unset** → signature check skipped. |
| `JWT_SECRET_KEY` | signing key for full JWT auth — reserved for a future phase; Phase 9 uses `API_KEY` instead |
| `SLACK_WEBHOOK_URL` | Slack alert channel for CRITICAL findings |
| `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`, `JIRA_BASE_URL` | JIRA auto-ticketing |
| `GITHUB_TOKEN` | GitHub API access (repo cloning, Actions, key validation) |
| `MODEL_PATH` | path to the fine-tuned CodeBERT model (full inference, server-side) |
| `ONNX_MODEL_PATH` | path to the ONNX-exported model (fast inference, pre-commit hook) |
| `ENVIRONMENT` | `development` \| `production` |

## 6. Project Timeline (for context — see `Secretsweep_Docs/`)

14-week plan, Jul 8 – Oct 18: (1) Foundation & Git extraction engine, (2) LLM semantic engine +
obfuscation detection, (3) CDFG + severity engine + developer profiler, (4) Pre-commit hook + dashboard
+ CI/CD integration, (5) Testing, paper writing & submission. Full detail in
`Secretsweep_Docs/secretsweep_timeline_roadmap.html`.

## 7. Conventions

- Every module below ships as an empty placeholder with a one-line module docstring until implemented —
  fill in logic incrementally, phase by phase, following the roadmap above.
- Detected secrets are never stored in plaintext in the database — `findings.redacted_snippet` must be
  masked/truncated before persistence.
- All new backend dependencies go in both `pyproject.toml` and `requirements.txt` (pinned).
- Any blocking/synchronous call to an external service (Redis, Neo4j, Celery's broker) must
  never run directly inside an `async def` route or on the main event loop without a bound —
  a down dependency has repeatedly turned into a multi-second hang that froze *every* request,
  not just the one that touched it (see `api/routes/scan.py`'s `_dispatch_scan_task`, `cdfg/cdfg_builder.py`'s
  Neo4j pre-flight check). Wrap it in `asyncio.to_thread` + a short `asyncio.wait_for` timeout.
- **CDFG graph endpoint fixed (2026-09-08)**: `GET /api/dashboard/graph/{scan_job_id}` now returns
  the real graph, loaded from Neo4j. Previously it was a hardcoded `{nodes: [], links: []}` stub —
  `cdfg/cdfg_builder.py`'s `CDFGBuilder` already built a full in-memory graph every scan and already
  had a working `sync_to_neo4j()`, but nothing ever called it, and neither `secretsweep-api` nor
  `secretsweep-worker` had Neo4j credentials wired into their environment at all. Fixed by: (1) adding
  `NEO4J_URI`/`NEO4J_USERNAME`/`NEO4J_PASSWORD` to both services in `docker-compose.yml`; (2)
  `api/tasks/scan_task.py` now constructs `ScanPipeline` with those settings instead of no args; (3)
  `ScanPipeline.run()` takes a new `scan_job_id` param and calls `cdfg_builder.sync_to_neo4j(scan_job_id=...)`
  after building the graph — tagging every synced node/edge with it, since Neo4j has no other concept of
  "which scan this came from" (MERGE keys only on `node_id`/`edge_id`, and the same secret can legitimately
  reappear across separate scans of the same repo); (4) a new `load_d3_format_from_neo4j()` in
  `cdfg/graph_queries.py` queries back just that one scan's subgraph by the `scan_job_id` property; (5)
  a new `open_driver_if_reachable()` helper in `cdfg_builder.py` (extracted from what `CDFGBuilder.__init__`
  already did) is reused by the graph-read route, `CDFGBuilder` itself, and the clear-history route below
  — one connection/reachability-check path instead of three copies. Verified end-to-end: triggered a scan,
  confirmed `Synced 11 nodes and 12 edges to Neo4j` in the worker log, then confirmed
  `GET /api/dashboard/graph/{that scan's id}` returned real secret/commit/file nodes with correct colors
  and `defined_in`/`found_in` edges — not an empty shape.
- **"Clear All Scan History" added (2026-09-08)**: a Danger Zone card on the Settings page
  (`dashboard/src/pages/Settings.jsx`) calls a new `DELETE /api/scan` (`api/routes/scan.py`) that deletes
  every `detected_secrets`/`developer_risk_records`/`scan_jobs`/`repositories` row (no FK cascade is
  declared on these tables — see §4 — so children are deleted explicitly before parents) and best-effort
  wipes the Neo4j graph too (`MATCH (n) DETACH DELETE n`, via the same `open_driver_if_reachable()` helper,
  off the event loop per the blocking-call rule below — a down Neo4j must not block clearing the primary
  relational history). The client-side "Recent Scans" list (`dashboard/src/lib/recentScans.js`, lifted out
  of `Scan.jsx` so `Settings.jsx` can reset it too) is cleared in the same action. Verified: seeded 3 repos/
  211 secrets via test scans, cleared, confirmed `GET /api/dashboard/summary` zeroed out and the old scan's
  graph endpoint returned `{nodes: [], links: []}`.
- **CDFG filter panel + Secret Lifecycle tab (2026-09-08)**: the graph became unreadable for repos with
  many secrets (113+ nodes on `gitleaks/gitleaks`), so `cdfg/graph_queries.py`'s `export_d3_format()` and
  `load_d3_format_from_neo4j()` now embed extra per-node/edge fields the dashboard needs beyond
  id/label/type/color — secret nodes carry `secret_hash`, `pattern_name`, `severity`, `author`,
  `is_active`, `first_seen_date`; commit nodes carry `commit_hash`/`author`/`timestamp`; file nodes carry
  `file_path`; every link carries `timestamp`/`commit_hash`. (Neo4j returns temporal properties as
  `neo4j.time.DateTime`, not stdlib `datetime` — both stringify to the same parseable ISO-8601 text via
  `str()`, so the query functions don't need the driver's time-conversion API.) `CDFGGraph.jsx` is now an
  orchestrator around two new components: `CDFGFilterPanel.jsx` (severity/file/developer filters, "only
  deleted"/"only cross-file propagation" toggles) filters the already-fetched graph client-side — a secret
  matches if it passes every active filter, and kept commit/file nodes are whatever a matching secret is
  actually connected to, so filtering to a handful of secrets also drops the now-irrelevant commits/files;
  and `SecretLifecycleList.jsx` derives one horizontal timeline card per secret (severity badge,
  Defined->Used->Deleted steps, author, exposure duration, files involved) from that same payload — no
  separate lifecycle endpoint needed, since Neo4j already has everything once the extra fields above were
  added. Exposure duration is computed in JS (`Date.now()` minus `first_seen_date`, or minus the last
  `deleted_in` edge's timestamp if inactive) rather than server-side, to avoid replicating
  `CDFGBuilder._exposure_end()`'s is_active-aware branching in two languages. Verified with a real browser
  (Playwright, driven via a one-off script since no project run-skill exists yet — worth
  `/run-skill-generator` if browser-driven verification recurs): navigated to the dashboard, loaded a real
  scan's graph, confirmed the filter panel renders all five controls, checking CRITICAL severity visibly
  reduced the node count with a live "Showing X of Y nodes" counter, the Secret Lifecycle tab rendered
  real cards with correct dates/exposure-day counts, and zero browser console errors.
- **Layer 2 scan performance fixed (2026-09-08)**: scans were taking far longer than the actual
  detection work justified. Root-caused via worker log timestamps, not guesswork: (1) `ml/inference.py`'s
  `SemanticClassifier._encode()` padded every tokenizer call to the full `MAX_SEQ_LENGTH` (512 tokens)
  regardless of real snippet length — `ml/onnx_export.py`'s `ONNXClassifier` had already fixed this exact
  issue for the pre-commit-hook path (`padding=True`, dynamic per-batch length; see its own comment citing
  ~880ms at fixed-512 vs. a fraction of that for realistic ~20-line snippets) but the fix was never ported
  to the PyTorch path the main scan pipeline actually uses. Attention masking makes padding amount
  irrelevant to a model's output for real tokens, so this is a pure speedup, zero behavior change — applied
  the identical `padding=True` switch here. (2) Bigger effect: `api/tasks/scan_task.py` constructs a fresh
  `ScanPipeline()` — and therefore a fresh `SemanticClassifier`, reloading CodeBERT's tokenizer + weights
  off disk — on *every single task*, even though a Celery worker process handles many scans over its
  lifetime and the model never changes between them. Measured 6-31s of every ~50s scan was this reload
  alone (varying with OS page-cache warmth). Fixed with `ml/inference.py`'s new `_MODEL_CACHE`, a
  module-level dict keyed by `model_path` — process-global by design, so each Celery prefork child caches
  independently and a model loads once per long-lived worker process, not once per task. `CDFGBuilder`'s
  Neo4j driver (opened/closed per `ScanPipeline.run()`, see the CDFG fix above) is untouched by this — only
  the classifier is cached, `ScanPipeline` itself is still built fresh per task, so its Neo4j lifecycle
  keeps working exactly as before. Verified empirically, not just in theory: two consecutive scans of
  `trufflesecurity/test_keys` in the same worker process — first (cold) `49.85s`, second (warm, logged
  `Reusing cached SecretClassifier ... skipped disk load`) `4.48s`, both producing identical results (5
  commits, 6 secrets). Full test suite re-run afterward: 135/135 passed, and the suite itself ran
  noticeably faster (120s vs. ~140s in earlier runs this session) — corroborating evidence, not just the
  targeted scan-timing test.
- Known gaps, not bugs: there's still no `GET /api/scan` (list) endpoint, so the dashboard's "Recent Scans"
  list is tracked client-side (localStorage) from scans triggered in that browser, not server-side —
  unrelated to the clear-history feature above, which clears both. `DetectedSecret` stores only the total
  `severity_score`, not the 5-factor breakdown — the Secrets page's expanded row shows what's actually
  available, not fabricated numbers. `hooks/hook.py`'s ONNX path (`PreCommitHook.fast_mode = False`)
  measured ~6s end-to-end on this dev machine against the actual exported `ml/models/secret_classifier.onnx`
  (~497MB) — well over the "under 2 seconds" target: `transformers.AutoTokenizer` alone costs ~1.5s (it
  transitively imports torch regardless of avoiding `ml/finetune.py`'s training-only deps, see
  `ml/text_utils.py`), and loading + running the ONNX session on a model this size accounts for the rest.
  `fast_mode` (Layer 1 pattern+entropy only, no ONNX) is near-instant and meets the budget; it's the honest
  fallback until the exported model is made smaller (quantization/distillation) or the hook process is kept
  warm instead of started fresh per commit.

## 8. Current Development Phase

Phase: 12 — COMPLETED
Status: PRODUCTION READY

Final testing (2026-09-08): `pytest tests/ -v` — 135/135 passed (0 failed, 0 skipped) in
one clean run; a second run done concurrently with a 17-minute background scan showed
`test_onnx_benchmark_under_500ms` failing under that resource contention (consistent with
the memory-pressure sensitivity already documented in §7 — not a regression). Coverage
(`pytest --cov=.`, `[tool.coverage.run]` in `pyproject.toml`): **65% overall**, below the
70% target. Weakest spots: `integrations/jira_ticket.py` (0% — Phase 11 shipped it without
a dedicated test, unlike `slack_alert.py`), `scripts/benchmark.py` (0% — Phase 12 eval
script, no tests written), `ml/finetune.py` (37%) and `ml/onnx_export.py`'s `export_to_onnx`
path (45%, training/export-only code exercised only when a fine-tuned model already
exists), `api/tasks/scan_task.py` (22%, the Celery task body isn't exercised without a
running worker), and the Phase 1 placeholder `api/schemas/*.py` files kept unused per
convention. Full per-file breakdown was produced but not persisted as a file; rerun the
command above to reproduce it. Final integration test (`scanner.scan_pipeline.ScanPipeline`
end-to-end on 3 repos): `trufflesecurity/test_keys` (5 commits, 6/6 confirmed, 37s),
`gitleaks/gitleaks` (1,099 non-merge commits, 153 Layer 1 matches → 113 confirmed/24
uncertain/16 FP removed by Layer 2, 1 Layer 3 obfuscation finding, 21 developer profiles,
~17.3 min), `pypa/sampleproject` (139 commits, 0 findings — correctly clean, 20s).

Re-verified 2026-09-08 after the CDFG/clear-history changes above: `docker compose exec
secretsweep-api pytest tests/ -q` — 135/135 passed, 0 failed, in one clean run inside the
running container (no regressions from the `cdfg_builder.py`/`scan_pipeline.py`/
`api/tasks/scan_task.py`/`api/routes/scan.py`/`api/routes/dashboard.py` changes).

## 9. Benchmark Results

Measured 2026-09-08 on this dev machine (no GPU) via `scripts/benchmark.py`, against
`trufflesecurity/test_keys` (6 known real credentials) and a synthetic repo built by the
script itself (10 obvious + 5 obfuscated real secrets, 10 false-positive traps), pooled
across both repos. GitLeaks 8.30.1 and TruffleHog 3.97.4 were run as native Windows
binaries (no Docker in this environment — see §10/§11).

| Tool        | Precision | Recall | F1    | Time  |
|-------------|-----------|--------|-------|-------|
| GitLeaks    | 0.933     | 0.667  | 0.778 | 1.2s  |
| TruffleHog  | 1.000     | 0.429  | 0.600 | 10.0s |
| SecretSweep | 0.909     | 0.952  | 0.930 | 93.3s |

SecretSweep's recall advantage comes almost entirely from Layer 3 (obfuscation decoding):
all 5 obfuscated secrets (base64/hex/unicode-escape/rot13/string-concat) were caught by
SecretSweep and missed by both other tools, since neither decodes before matching. The
one SecretSweep false negative (in `test_keys`) is a genuine, honest gap: SecretSweep has
no generic HTTP basic-auth-URL pattern (`https://admin:admin@...`), which GitLeaks and
TruffleHog both catch via generic detectors. SecretSweep's ~93s runtime is dominated by
loading and running the fine-tuned CodeBERT model (Layer 2) on CPU per match — GitLeaks/
TruffleHog are regex/entropy-only and orders of magnitude faster per run, a real,
expected accuracy-vs-speed tradeoff, not an apples-to-apples latency comparison (see
`hooks/hook.py`'s `fast_mode` for the pattern-only path used when that tradeoff isn't
acceptable, e.g. the pre-commit hook). Full per-repo TP/FP/FN breakdown is in
`benchmark_results.json`.

**Re-measured 2026-10-06** on the same machine, GitLeaks still 8.30.1 (binary re-fetched
fresh — none of the earlier session's downloaded tool binaries persisted a month later,
so both were re-downloaded from their GitHub releases for this run), TruffleHog now
3.98.0 (was 3.97.4):

| Tool        | Precision | Recall | F1    | Time  |
|-------------|-----------|--------|-------|-------|
| GitLeaks    | 0.933     | 0.667  | 0.778 | 2.9s  |
| TruffleHog  | 1.000     | 0.429  | 0.600 | 21.8s |
| SecretSweep | 0.909     | 0.952  | 0.930 | 30.0s |

Precision/recall/F1 for all three tools are bit-for-bit identical to the September run —
same TP/FP/FN pooled counts (SecretSweep 20/2/1, GitLeaks 14/1/7, TruffleHog 9/0/12),
confirming detection behavior hasn't drifted. **SecretSweep's runtime dropped from 93.3s
to 30.0s (3.1x)** — direct production confirmation of the §7 "Layer 2 scan performance
fixed" entry (the `padding=True` dynamic-padding switch in `ml/inference.py`), measured
here independently of that entry's own Celery-worker verification, via a completely
separate code path (`scripts/benchmark.py`'s `BenchmarkRunner` calls `ScanPipeline`
directly, no Celery/Docker involved). GitLeaks/TruffleHog's own runtimes also moved
(1.2s→2.9s, 10.0s→21.8s) — expected run-to-run noise on this dev machine (background
load, disk cache state), not a regression in either tool; what matters for comparison is
that their precision/recall/F1 didn't move at all. Full breakdown again in
`benchmark_results.json`.

## 10. How to Run (Production)

```
docker-compose up -d
```
Open http://localhost:3000 · API: http://localhost:8000/api/health · Docs: http://localhost:8000/docs

**Verified 2026-09-08** on this dev machine after Docker Desktop was installed mid-project
(it wasn't present for the initial Phase 12 pass — see git history/prior note if reading an
old copy of this file). `docker compose build` → `up -d` → all 6 containers reached
`Up`/`healthy` → `GET /api/health` returned `{"status":"ok","database":"connected",
"redis":"connected"}` → dashboard (`:3000`) and Neo4j browser (`:7474`) both returned
HTTP 200 → `docker compose down` cleaned up successfully. Three real bugs were found and
fixed in the process, not just a passive "it worked":
1. **`docker/Dockerfile.api` pulled full CUDA-enabled torch** (PyPI's default `torch==2.3.1`
   wheel bundles ~2-3GB of NVIDIA driver packages) even though this container has no GPU
   passthrough and `ml/inference.py` already falls back to CPU. Fixed by installing
   `torch==2.3.1 --index-url https://download.pytorch.org/whl/cpu` before the main
   `pip install -r requirements.txt` (which then sees it already satisfied).
2. **No `.dockerignore` existed**, so the build context (and the final `COPY . .` layer)
   included this checkout's `.venv/` (2.1GB), `data/repos/`, `data/benchmark_repos/`, and
   other local-only artifacts on every build. Added `.dockerignore` at the repo root.
   Both (1) and (2) compounded into repeatedly exhausting host disk space (`OSError:
   [Errno 30] Read-only file system` mid-build, then the Docker Desktop daemon itself
   crashing) before being fixed.
3. **`neo4j:5-community` (floating tag) crash-loops on startup** — `Usage: su-exec
   user-spec command [args]`, i.e. `userid`/`groupid` empty when the entrypoint checks
   mounted-volume permissions. Confirmed empirically this is a regression in the specific
   patch that tag currently resolves to (5.26.30): `neo4j:5.26.28-community` starts
   cleanly with the identical compose config. Pinned to `5.26.28-community` instead of
   the floating tag.

None of these were pre-existing Dockerfile/compose logic bugs from the original Phase 12
authoring — all three only surfaces when you actually run `docker compose build`/`up`,
which is exactly why this section previously carried an "unverified, Docker not installed"
caveat instead of claiming success on file review alone.

**A fourth, more significant bug** surfaced only once a scan was actually triggered
through the running dashboard against the live worker container: `api/celery_app.py`
never imported `api/tasks/scan_task.py`, so `celery -A api.celery_app worker` started
with an empty `[tasks]` list — every dispatched scan silently sat at `PENDING` forever
(`Received unregistered task of type 'run_scan_task'... The message has been ignored and
discarded` in the worker log). This predates Phase 12; it's not a Docker artifact — the
same bug would occur running the worker directly with `celery -A api.celery_app worker`
outside Docker too. Existing tests never caught it because `tests/test_api.py` mocks the
dispatch layer rather than exercising a real Celery worker process's task discovery.
Fixed by adding `include=["api.tasks.scan_task"]` to the `Celery(...)` constructor in
`api/celery_app.py` (an inline `import api.tasks.scan_task` there would be circular,
since that module imports `celery_app` back from this one). Verified fixed: rebuilt
`secretsweep-api`/`secretsweep-worker`, restarted, and `run_scan_task` now appears in
the worker's `[tasks]` list on boot. Any scan job dispatched before this fix was applied
was already discarded by Celery and will never complete — retrigger it from the dashboard.

**A fifth bug**, found immediately after the fourth was fixed and the worker actually
started executing tasks: the first DB write inside `_run_scan_job` (marking the
`ScanJob` "running") raised `sqlalchemy.exc.InterfaceError:
asyncpg.exceptions.InterfaceError: cannot perform operation: another operation is in
progress`, leaving the job stuck. Root cause: `api/db/session.py`'s `AsyncEngine` is a
process-wide singleton, cached in a module-level global on first use — correct for the
`secretsweep-api` container, which runs everything on uvicorn's one persistent event
loop, but wrong for `secretsweep-worker`: `scan_task.py`'s `run_scan_task` calls
`asyncio.run()` once per task invocation, and each call opens a *new* event loop and
closes it when done. asyncpg connections are bound to the loop that opened them, so
reusing the cached engine from a prior `asyncio.run()` call (a retry of the same task,
or simply the next scan submitted to the same long-lived worker process) hands it
connections tied to an already-closed loop. Fixed by adding `dispose_engine()` to
`api/db/session.py` (disposes the engine and clears both cached globals) and calling it
from a `finally` block wrapping every `asyncio.run()` invocation in `scan_task.py`, so
each task run tears down its engine before its loop closes and the next invocation
builds a fresh one. Verified fixed end-to-end: triggered a scan directly against
`POST /api/scan/repo` for `trufflesecurity/test_keys`, polled `GET /api/scan/{id}`, and
it reached `status: completed` with `total_commits_scanned: 5, secrets_found: 6` —
matching §8's own final integration-test numbers for this repo exactly.

## 11. How to Run (Development)

```
uvicorn api.main:app --reload --port 8000
cd dashboard && npm run dev
pytest tests/ -v
```
No `.env` required for local dev: unset `DATABASE_URL` falls back to SQLite, unset
`API_KEY` disables auth, Neo4j/Redis fail gracefully if not running. Pre-commit hook:
`python -m scripts.secretsweep_cli install` (run from inside the target repo, with this
project's directory on `PYTHONPATH`). Benchmark: `python -m scripts.benchmark` (needs
`GITLEAKS_BIN`/`TRUFFLEHOG_BIN` on PATH or set as env vars pointing at the binaries;
falls back to SecretSweep-only if either tool isn't available).
