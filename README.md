# SecretSweep AI

LLM-augmented semantic data-flow analysis for proactive credential leakage detection and developer risk governance across Git repositories.

## Architecture

```
                                   ┌─────────────────────────┐
                                   │   secretsweep-dashboard │
                                   │      (React, :3000)     │
                                   └────────────┬─────────────┘
                                                │ REST/JSON
                                                ▼
┌───────────────┐   git history   ┌─────────────────────────┐
│  Git repos      │ ─────────────▶ │     secretsweep-api      │
│ (GitHub/GitLab)│                 │     (FastAPI, :8000)     │
└───────┬───────┘                 └───────┬─────────┬─────────┘
        │                                 │         │
        │ pre-commit hook                 │         │
        │ (ONNX, <2s)                     │         │
        ▼                                 ▼         ▼
┌───────────────┐                 ┌─────────────┐ ┌─────────┐
│    hooks/      │                 │ postgresql  │ │  redis  │
│ pre_commit_hook│                 │   :5432     │ │  :6379  │
└───────────────┘                 └─────────────┘ └─────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────┐
│                    scanner/  (Layer 1 + Layer 2)             │
│  git_extractor → regex_scanner + entropy_scorer (Layer 1)    │
│               → obfuscation_decoder + semantic_engine        │
│                 (Layer 2, fine-tuned CodeBERT)                │
└───────────────────────────┬────────────────────────────────┘
                            ▼
                  ┌──────────────────┐        ┌─────────┐
                  │  cdfg/            │ ─────▶ │  neo4j  │
                  │  graph_builder     │        │  :7687  │
                  │  severity_engine   │        └─────────┘
                  └────────┬──────────┘
                           ▼
              ┌────────────────────────┐
              │ validators/ (active key │
              │ liveness) + profiler/   │
              │ (developer risk)        │
              └────────────┬────────────┘
                           ▼
              ┌────────────────────────┐
              │ integrations/           │
              │ Slack + JIRA + GitHub   │
              │ Actions (CI/CD)         │
              └────────────────────────┘
```

## Quick Start

```bash
# 1. Clone
git clone <this-repo-url> secretsweep-ai
cd secretsweep-ai

# 2. Configure environment
cp .env.example .env
# edit .env with real DATABASE_URL, NEO4J_*, SLACK_WEBHOOK_URL, JIRA_*, GITHUB_TOKEN, etc.

# 3. Launch the full stack
docker-compose up --build
```

- API: http://localhost:8000 (docs at `/docs`)
- Dashboard: http://localhost:3000
- Neo4j Browser: http://localhost:7474
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

### Local (non-Docker) backend dev

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn api.main:app --reload
```

### Local dashboard dev

```bash
cd dashboard
npm install
npm run dev
```

## Module Overview

| Module | Purpose |
|---|---|
| `api/` | FastAPI app — routers, services, SQLAlchemy models, Pydantic schemas, auth |
| `scanner/` | Layer 1 (Git history extraction, regex patterns, Shannon entropy) + Layer 2 (obfuscation decoding, CodeBERT semantic classification) |
| `ml/` | Dataset building, CodeBERT/UniXcoder fine-tuning, ONNX export, shared inference |
| `cdfg/` | Credential Data Flow Graph — NetworkX construction, Neo4j persistence, cross-commit traversal, 5-factor severity scoring |
| `validators/` | Active credential liveness checks (AWS, Stripe, GitHub) |
| `profiler/` | Aggregates findings into per-developer risk scores and trends |
| `hooks/` | Pre-commit Git hook (ONNX inference, <2s) and installer |
| `integrations/` | Slack alerting, JIRA auto-ticketing, GitHub Actions CI/CD workflow |
| `dashboard/` | React + Vite + TailwindCSS frontend (repository / developer / timeline / severity views) |
| `tests/` | Unit and API test suite |
| `scripts/` | Benchmark evaluation (vs GitLeaks/TruffleHog) and DB seeding |
| `data/` | Fine-tuning datasets and model weights (gitignored) |

## Environment Variables

See [`.env.example`](.env.example) for the full list: `DATABASE_URL`, `NEO4J_URI` / `NEO4J_USERNAME` / `NEO4J_PASSWORD`, `REDIS_URL`, `JWT_SECRET_KEY`, `SLACK_WEBHOOK_URL`, `JIRA_API_TOKEN` / `JIRA_PROJECT_KEY` / `JIRA_BASE_URL`, `GITHUB_TOKEN`, `MODEL_PATH`, `ONNX_MODEL_PATH`, `ENVIRONMENT`.

## Project Docs

Full project spec, database schema, and structure live in [`CLAUDE.md`](CLAUDE.md). Timeline and phase breakdown live in `Secretsweep_Docs/`.
