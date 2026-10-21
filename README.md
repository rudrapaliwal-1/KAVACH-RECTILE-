# KAVACH-X

**Brand Tagline:** "Find the Vulnerability. Prove the Fix."  
**Product Positioning:** AI-assisted security remediation with explicit human approval, independent verification, and inspectable evidence.

*Note: The official product name is **KAVACH-X**. Internal module names, environment variables, and Docker tags retain compatibility aliases where needed.*

## Implementation & Architecture
The current scan and dashboard capabilities, executed tests, setup, and limitations are documented in [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) and [TEST_REPORT.md](TEST_REPORT.md). The protected BOLA workflow provides an independently verified remediation adapter.

# SENTINEL-X Phase 5 local integration

This workspace combines Agent A, Agent B, the backend, its independent Docker verifier, and the team's React frontend. The frontend is now installed and locally integrated; see `FRONTEND_LOCAL_INTEGRATION_REPORT.md` for the executed browser-to-Docker fixture test and startup instructions. On Windows, start `scripts/start_local_backend.ps1 -CopyToken` and `scripts/start_local_frontend.ps1` in separate PowerShell windows, then open http://localhost:5173 and connect with the copied operator token. Fresh AI generation still requires the configured Ollama model.

Historical Phase 5 evidence reports a genuine Ollama patch passing backend policy and, after exact-hash human approval, independent Docker verification. That verification request replayed the saved AI proposal rather than performing a second inference call. Exact evidence and limits are recorded in `PHASE5_INTEGRATION_REPORT.md`.

## Requirements

- Python 3.12, Docker with a running daemon, Node.js and npm when the frontend arrives, and local Ollama.
- A model available to Ollama, preferably `qwen2.5-coder:7b`.
- A private operator token of 32–256 ASCII characters. Set it in the environment; never commit it. `NEATLOGS_API_KEY` is optional for hosted telemetry and must also come from a secret manager.

## Setup

From this directory:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt -r verification/requirements.txt neatlogs
ollama pull qwen2.5-coder:7b
docker build -t sentinel-verification-lab:latest -f verification/Dockerfile verification/
```

Load the non-secret variables from `.env.example`, set `SENTINEL_OPERATOR_TOKEN` privately, and start the backend:

```bash
set -a; source .env.example; set +a
export SENTINEL_OPERATOR_TOKEN="<replace with a private 32–256 character token>"
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Check `http://127.0.0.1:8000/health` and `/ready`. The planner import configured by `SENTINEL_AGENT_CALLABLE` is `agent.planner:propose_patch`. The backend supplies only the authorized `app/access.py` context. Agent A asks the real model for a narrowly constrained ownership guard, validates its syntax, and computes a unified diff from authorized source. The backend validates the proposal; operator approval and Docker verification remain separate.

## Demo flow

1. Submit an authorized finding through `POST /api/findings` with `X-Operator-Token`.
2. Read `GET /api/jobs/{job_id}/patch` and inspect the exact diff and SHA-256 hash.
3. A human operator decides whether to `APPROVE` that hash through `POST /api/jobs/{job_id}/approval`.
4. Run `POST /api/jobs/{job_id}/verify` and inspect `/evidence` and `/events`.
5. If verification fails, the backend requests attempt 1 or 2 from the planner using sanitized retry feedback. Review and approve the new hash separately before another verification run.

A proposal is verified only after the separate approval and Docker step. Protected tests run only in the independent verifier. To smoke-test local inference without approving or applying a patch, run `PYTHONPATH=. .venv/bin/python scripts/real_inference_smoke.py`; it writes a private proposal artifact under `/tmp`.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest agent/tests backend/tests verification/tests -q -p no:cacheprovider --tb=short
.venv/bin/python -m neatlogs doctor --local --json
```

The fixture integration test in `agent/tests/test_fixture_integration.py` uses named fixture diffs to exercise wiring and real Docker verification. It does not test model quality. Hosted Neatlogs export requires `NEATLOGS_API_KEY` and a separate authenticated Doctor probe.

## VibeCI Local Verification & Preflight
KAVACH-X integrates the verified capabilities of **VibeCI** (MIT License, created by Piyush Kumar) as a modular, local development-quality and security preflight verification engine.

### Capabilities:
- **Layer 1: Static Health & Preflight:** Secret scanning across 13 credential formats, environment variable audit against `.env.example`, serverless platform limits, and linters/typecheckers.
- **Layer 2: Production Build Verification:** Automated build bundle testing (`npm run build`, `uv build`).
- **Layer 3: Existing Unit Tests:** Discover and run `pytest`, `vitest`, `jest`, `bun test`.
- **Layer 4: Runtime Smoke Testing:** Background process boot & HTTP readiness probing.
- **Layer 5: Honest Unverified Accounting:** Clear documentation of software boundaries that remain unverified (e.g. database, 3rd party APIs).
- **AI Coding Agent Rules:** 1-click configuration for Cursor, Claude Code, Copilot, and Antigravity.

### Running VibeCI Tests:
```bash
python -m pytest backend/tests/test_vibeci_integration.py -v
python -m pytest vibeci/tests -q
```

Detailed architecture and API specifications are in [docs/VIBECI_INTEGRATION.md](docs/VIBECI_INTEGRATION.md).
