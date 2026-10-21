# KAVACH-X Frontend

React + TypeScript + Vite frontend for **KAVACH-X — AI-assisted security remediation with explicit human approval, independent verification, and inspectable evidence**.

**Brand Tagline:** "Find the Vulnerability. Prove the Fix."

## Current implementation status

- Overview dashboard and status distribution sourced from `GET /api/jobs`.
- Findings table and predefined BOLA demonstration submission via `POST /api/findings`.
- Investigation page for `GET /api/jobs/{job_id}`, `/patch`, and `/events`.
- Patch diff display and backend-bound approve/reject actions using the current `patch_hash`.
- Verification request and result display; the UI does not invent test evidence.
- Activity timeline loaded from backend workflow events.
- Evidence retrieval and JSON download from `GET /api/jobs/{job_id}/evidence`.
- Loading, timeout, network failure, empty-state and invalid-job feedback.
- Responsive dark operations dashboard.

**Integration caveat:** these pages target the planned API contract supplied to the frontend team. The repository backend could not be inspected in this environment, so actual field names, response envelopes, approval semantics and verification behavior still need confirmation against FastAPI. Do not describe this as end-to-end validated until that check is complete.

## Requirements

- Node.js 20+ (tested target: Node 22)
- npm
- FastAPI backend running and reachable from the browser

## Run locally

```bash
cd frontend
cp .env.example .env
# Edit VITE_API_BASE_URL to the FastAPI origin, e.g. http://localhost:8000
npm install
npm run dev
```

Open <http://localhost:5173>.

Vite environment variables are read at dev-server startup; restart Vite after changing `.env`.

## Validate

```bash
npm run typecheck
npm run build
```

## API configuration and CORS

`VITE_API_BASE_URL` is the origin only, without a trailing slash. The browser calls the API directly, so configure FastAPI CORS to allow the frontend origin (typically `http://localhost:5173`) for the required methods and headers.

The API client uses a 15-second request timeout. The timeout can be adjusted in `src/api/client.ts`.

## Routes

| Route | Purpose |
|---|---|
| `/` | Overview dashboard |
| `/findings` | Findings/jobs table and BOLA demo submission |
| `/jobs/:jobId` | Investigation, patch diff, approval, verification, event history |
| `/investigation` | Guidance to select a job |
| `/activity` | Query workflow events by job ID |
| `/evidence` | Retrieve and download backend evidence JSON |
| `/verification` | Redirects to findings; verification details are per job |

## API calls

- `GET /health`
- `POST /api/findings`
- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `GET /api/jobs/{job_id}/patch`
- `POST /api/jobs/{job_id}/approval` with `{ "patch_hash": "...", "decision": "APPROVE" | "REJECT" }`
- `POST /api/jobs/{job_id}/verify`
- `GET /api/jobs/{job_id}/evidence`
- `GET /api/jobs/{job_id}/events`

## Security and correctness notes

- Approval and rejection are not local-only toggles. The UI posts the hash returned by the current patch endpoint and refreshes after backend confirmation.
- Approval controls are disabled unless the job or patch indicates a pending approval. Confirm the backend's exact state values before demo.
- Verification output is only displayed when supplied by the API. Passing the required tests is not represented as proof that the whole application is secure.
- Evidence download serializes the backend response object without adding claims or test results.
- Do not expose secrets in frontend environment variables. Vite `VITE_*` values are bundled into browser code.
- The browser must not be trusted as the security boundary. Enforce patch hash matching, policy validation, approval invalidation on revision, authorization, and isolated execution on the backend.

## Known contract questions for the backend owner

1. Does `GET /api/jobs` return an array or `{ "jobs": [...] }`? Both are normalized.
2. Are job details flat, or nested under a `job` field?
3. What is the exact response schema for patch files and unified diff text? Current viewer supports `patch.files[].diff` or `patch.diff`.
4. What exact `approval_status` values are returned, and is `job.status === "AWAITING_APPROVAL"` authoritative?
5. Does `POST /api/jobs/{job_id}/verify` return a result immediately, or return a queued job requiring polling?
6. Are events returned as an array or `{ "events": [...] }`?
7. Does evidence endpoint return JSON directly, and what audit/provenance fields are guaranteed?
8. Confirm CORS and whether approval requires any extra concurrency/version token beyond `patch_hash`.

## Git handoff

This generated frontend is a standalone working directory. The remote repository could not be fetched from this environment, so no changes were made to the remote `feat/frontend` branch and no commit or pull request was created. Copy/merge `frontend/` into the repository's `feat/frontend` branch after reviewing the backend contracts.


## Dark editorial frontend refresh

The interface uses a black editorial canvas, white display typography, italic Bodoni-style page/section headings, and high-contrast cyan, hot-pink, and yellow accents. Cards and controls have visible offset shadows and lift/rotation hover states. The dashboard intentionally separates the overview/status area from the remediation queue with a large divider to create a scroll-based first fold. Existing backend-driven data and workflows are preserved.

### Run locally

Run these commands **from the project root (the directory containing `package.json`)**:

```bash
npm install
npm run dev
```

Open the local URL printed by Vite. Keep the terminal running while using the site. Set `VITE_API_BASE_URL` in `.env` if the backend is not available at the configured default.
