# KAVACH-X / SENTINEL-X — Comprehensive Implementation Audit

**Audit Date:** 2026-10-20  
**Repository Branch:** `feat/main`  
**Platform Target:** Editorial Sci-Fi Security Operations Platform (KAVACH-X / SENTINEL-X)

---

## 1. Executive Architecture Map

The system is organized into a modular full-stack architecture preserving strict security boundaries:

```
[ Frontend: React 18 / Vite / TS ]
       |
       | (Credentials: Cookies + CSRF + Bearer)
       v
[ Backend: FastAPI (backend/main.py) ]
       |
       +---> [ Auth & Middleware (ApiGuard, CSRF, Token Auth) ]
       +---> [ SQLite Database (backend/database.py - WAL mode, strict transactions) ]
       +---> [ Workflow Orchestrator (backend/workflow.py) ]
       |        |
       |        +---> [ Agent Planner (agent/planner.py via ConfiguredAgentAdapter) ]
       |        +---> [ Policy Validator (backend/policy.py - Canonical SHA-256) ]
       |        +---> [ Isolated Verifier (verification/adapter.py -> Docker Lab) ]
       |
       +---> [ Routes: projects, scans, scan_patches, jobs, findings, approvals, verification ]
```

---

## 2. Confirmed Root Causes of Workflow Disconnects

### Root Cause A: Projects Page Duplicate Entries & `Unavailable` Source Revisions
1. **Orphaned `CREATED` Projects:** `POST /api/projects` created a database row with `status: 'CREATED'`. The client then called `POST /api/projects/{id}/upload`. If upload was retried, canceled, or encountered an error, the empty `CREATED` row remained indefinitely in the database. Subsequent uploads created new IDs with identical names.
2. **Missing Source Revision for General Uploads:** In `backend/routes/projects.py` (line 193), `revision` was calculated as `TARGET_MANIFEST.source_revision(...) if supported else None`. Because `TARGET_MANIFEST.source_revision` strictly requires the BOLA test paths (`app/access.py`), any non-BOLA project received `revision = None`, displaying `"Unavailable"` in the UI. In `upload_file`, `source_revision` was never updated.
3. **Missing Scan History Finding Counts:** In `backend/routes/scans.py`, `GET /api/projects/{id}/scans` queried `SELECT * FROM project_scans` without aggregating `finding_count`, causing the scan history to show undefined counts.

### Root Cause B: Agent Activity Disconnected Timeline
1. **Manual ID Entry Barrier:** `Activity.tsx` lacked an initial fetch of the user's recent jobs. It required operators to manually type a raw UUID job ID into an empty text field.
2. **Missing Deep-Link Parameter Handling:** Navigating to `/activity?jobId=...` from the Command Center or Findings was ignored.
3. **Format Normalization:** While `Workflow.events` returns an array of events, `unwrapList` in `api/jobs.ts` required clean typing to seamlessly feed `ActivityTimeline`.

### Root Cause C: Incomplete Verification Matrix and Evidence Exploration
1. **Missing Individual Test Breakdown in Verification Page:** `Verification.tsx` condensed all test outcomes into a single text string rather than rendering individual test results (`PASSED`/`FAILED`), durations, and exact canonical patch hashes.
2. **Evidence Page Manual Lookup:** `Evidence.tsx` required manually typing a Job ID or Scan Patch ID without providing a clickable list of the user's completed jobs.

### Root Cause D: UI Form Layout Collisions & Absolute Search Bar Overlap
1. **Unstyled Inline Form Elements:** `Projects.tsx` form controls lacked vertical form-group block styling, causing labels and inputs to collapse horizontally onto a single line.
2. **Absolute Center Topbar Search:** `.header-search` used `position: absolute; left: 50%`, causing it to overlap navigation buttons and user email chips on smaller viewports.

---

## 3. Existing Functionality That Works

1. **Exact-Hash Human Approval Security:** Backend policy enforces canonical SHA-256 patch hashing (`backend/policy.py`). Modifying a patch proposal or attempting to approve a stale hash correctly fails with `409 Conflict` or rejection.
2. **Deterministic State Machine:** Transitions across `FINDING_RECEIVED`, `PLANNING`, `AWAITING_APPROVAL`, `VERIFYING`, `VERIFIED`, `VERIFICATION_FAILED`, `POLICY_REJECTED`, `USER_REJECTED`, `RETRY_EXHAUSTED`, `EXECUTION_ERROR` are tracked in SQLite `workflow_events` with append-only integrity triggers.
3. **Isolated Docker Lab Design:** Untrusted candidate patches are never executed directly on the host. When Docker is active, it runs protected test suites inside `sentinel-verification-lab:latest`. When Docker is offline, it safely reports `EXECUTION_ERROR` without fabricating results.
4. **Readiness Probe:** `GET /ready` probes SQLite, Ollama HTTP, model weights, Docker engine, verifier image, and patch utility.

---

## 4. Test Baseline (Prior to Phase One Fixes)

- `pytest backend/tests/test_case_page_and_evidence.py`: **7 passed**
- `pytest backend/tests -m "not docker"`: **104 passed, 2 skipped**
- `pytest agent/tests -m "not docker"`: **54 passed, 32 subtests passed**
- `frontend` typecheck: **0 errors**
- `frontend` production build: **Passed**

---

## 5. Ordered Implementation Plan

1. **Phase One:** authoritatively bind endpoints and ensure API client consistency.
2. **Phase Two:** Implement deterministic `compute_source_revision` in `backend/routes/projects.py`, prevent duplicate `CREATED` projects, add finding counts to `project_scans`, and add project deletion.
3. **Phase Three:** Verify end-to-end remediation pipeline with exact-hash binding.
4. **Phase Four:** Rebuild `Activity.tsx` with automatic recent job loading, deep-link support, and interactive timeline.
5. **Phase Five:** Ensure Command Center cards and lifecycle distribution are fully connected to real backend endpoints.
6. **Phase Six:** Upgrade `Verification.tsx` and `Evidence.tsx` to provide comprehensive individual test breakdowns and 1-click evidence inspection.
7. **Phase Seven:** Polish UI responsive layouts, forms, and accessibility.
8. **Phase Eight:** Validate security controls and execute regression test suites.
9. **Phase Nine & Ten:** Final documentation and verification report.
