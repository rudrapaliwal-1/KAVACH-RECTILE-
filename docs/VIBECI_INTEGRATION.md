# VibeCI Integration in KAVACH-X

## 1. Executive Summary & Attribution
**VibeCI** is an open-source, local-first verification engine created by **Piyush Kumar** ([GitHub: piyush588/vibeCI](https://github.com/piyush588/vibeCI), MIT License).

Its primary purpose is to catch software defects, hardcoded credentials, missing environment variables, build compilation errors, and broken runtime states locally in sub-seconds before code reaches remote CI or production environments.

In **KAVACH-X**, VibeCI is integrated as an in-process preflight and development-quality verification engine that bridges static triage with independent verification.

---

## 2. Integrated Capabilities
VibeCI operates across **5 distinct verification layers**:

### Layer 1: Static Health & Environment Preflight
- **Secret Leak Scanner (`SecretScanner`):** Identifies 13 categories of leaked cryptographic keys, API credentials, and database connection strings with passwords (AWS, GitHub, GitLab, OpenAI, Claude, Gemini, Hugging Face, Stripe, Slack, database URIs).
- **Environment Auditor (`EnvAuditor`):** Cross-references recognized environment variable access (`process.env`, `import.meta.env`, `os.environ`, `os.getenv`) against `.env.example` to catch missing configurations.
- **Platform Preflight:** Audits platform-specific serverless function deployment limits (e.g., Vercel Hobby 12-function limit).
- **Linters & Typecheckers:** Automated discovery and execution of configured tools (`ruff`, `mypy`, `flake8`, `tsc`, `eslint`, `biome`).

### Layer 2: Production Build Verification
- **Build Verifier (`BuildVerifier`):** Detects package managers (`npm`, `pnpm`, `yarn`, `bun`, `uv`) and executes production build commands (`npm run build`, `uv build`) to guarantee that bundling and compilation succeed.

### Layer 3: Behavior & Existing Unit Tests
- Detects and executes existing test suites (`pytest`, `vitest`, `jest`, `bun test`) with non-interactive flags.

### Layer 4: Runtime Smoke Testing
- **Runtime Smoke Tester (`RuntimeSmokeTester`):** Starts the application process in a background session, waits for port readiness, probes configured HTTP routes (`/`), validates non-500 HTTP responses, and terminates all child processes cleanly without orphaned listeners.

### Layer 5: Honest Unverified Accounting
- **Honest Boundaries (`identify_unverified_capabilities`):** Accurately accounts for unverified capabilities (such as installed database drivers with no test database, unexercised third-party APIs, or missing browser E2E test suites) instead of presenting an empty guarantee of complete correctness.

### Change-Aware Verification
- **Git Change Analyzer (`GitChangeAnalyzer`):** Inspects working tree diffs and staged files to target checks only on modified source files and related tests.

### AI Assistant Instruction Generator
- **Rule Installation (`install_rules`):** Generates and installs instructions into `.cursorrules`, `CLAUDE.md`, `.github/copilot-instructions.md`, and `AGENTS.md`.

---

## 3. Architecture & Integration Boundaries

```
┌──────────────────────────────────────────────────────────┐
│                     KAVACH-X UI                          │
│     (frontend/src/pages/Verification.tsx & Projects.tsx) │
│              VibeCIPanel Component                       │
└────────────────────────────┬─────────────────────────────┘
                             │ HTTP REST API
┌────────────────────────────▼─────────────────────────────┐
│             backend/routes/vibeci.py                     │
│    - GET  /api/vibeci/status                             │
│    - POST /api/projects/{id}/vibeci/preflight            │
│    - POST /api/projects/{id}/vibeci/verify               │
│    - GET  /api/projects/{id}/vibeci/reports              │
│    - GET  /api/projects/{id}/vibeci/rules                │
│    - POST /api/projects/{id}/vibeci/rules                │
└────────────────────────────┬─────────────────────────────┘
                             │ Service Contract
┌────────────────────────────▼─────────────────────────────┐
│          backend/services/vibeci_service.py              │
│  - Path Containment (Traversal Protection)               │
│  - Explicit Timeouts (1s - 120s)                         │
│  - Secret Masking & Output Size Bounds (64 KB)           │
│  - Cross-Platform Venv Resolution (Scripts / bin)        │
└────────────────────────────┬─────────────────────────────┘
                             │ In-Process Library
┌────────────────────────────▼─────────────────────────────┐
│                     vibeci/                              │
│  - Engine Coordinator & Multi-Layer Runners              │
│  - Secret Scanner, Env Auditor, Build & Smoke Testers    │
│  - Detectors (Python, JavaScript, Vercel)                │
└──────────────────────────────────────────────────────────┘
```

---

## 4. Security & Safety Safeguards
1. **Path Containment:** All inspections and commands validate that target files are strictly contained within the project's authorized root directory (`validate_contained_path`), preventing directory traversal attacks.
2. **Secret Redaction:** Any detected secret tokens or database passwords matching credential patterns are masked (`[REDACTED_CREDENTIAL]`) before persisting reports in SQLite or returning them over the API.
3. **Execution Timeouts:** Subprocesses are bounded by strict timeouts (default 30s, max 120s) and killed via process tree termination on timeout.
4. **Output Size Capping:** Process output is bounded at 64 KB to protect against memory exhaustion.
5. **Separation of Concerns:** VibeCI preflight and verification provide development-quality feedback. They never substitute for human approval or Docker-isolated cryptographic attestation in KAVACH-X.

---

## 5. API Reference

### 1. `GET /api/vibeci/status`
Returns integration status, supported verification layers, and detected host tools.
**Response:**
```json
{
  "service": "vibeci",
  "version": "0.3.0",
  "available": true,
  "available_layers": ["static_health", "env_audit", "security", "build", "behavior", "runtime_smoke", "honest_boundaries"],
  "detected_tools": {
    "pytest": true,
    "npm": true,
    "pnpm": false,
    "yarn": false,
    "bun": false,
    "uv": false,
    "ruff": false,
    "mypy": false,
    "tsc": true,
    "git": true
  },
  "default_timeout_seconds": 30,
  "max_timeout_seconds": 120
}
```

### 2. `POST /api/projects/{project_id}/vibeci/preflight`
Runs fast sub-second preflight checks (secrets, env audit, platform limits, and honest accounting). Completely non-executing.

### 3. `POST /api/projects/{project_id}/vibeci/verify`
Runs multi-layer verification on the project source.
**Request Body:**
```json
{
  "run_static": true,
  "run_build": false,
  "run_tests": true,
  "run_smoke": false,
  "changed_only": false,
  "timeout_seconds": 30
}
```

### 4. `GET /api/projects/{project_id}/vibeci/reports`
Lists historical VibeCI verification runs for the project.

### 5. `POST /api/projects/{project_id}/vibeci/rules`
Installs or updates AI coding agent instructions (`agent`: `"all"`, `"cursor"`, `"claude"`, `"copilot"`, `"universal"`, or `"antigravity"`).

---

## 6. Verification & Testing

### Run Integration Tests:
```bash
python -m pytest backend/tests/test_vibeci_integration.py -v
```

### Run VibeCI Engine Unit Tests:
```bash
python -m pytest vibeci/tests -q
```

---

## 7. License & Upstream Attribution
VibeCI is licensed under the MIT License.
Copyright (c) 2026 Piyush Kumar.
Source repository: [https://github.com/piyush588/vibeCI](https://github.com/piyush588/vibeCI).
Preserved under `vibeci/LICENSE`.
