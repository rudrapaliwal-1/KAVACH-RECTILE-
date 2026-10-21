# IMPLEMENTATION REPORT — KAVACH-X / SENTINEL-X
## Platform Repair, Stabilization, and Production Hardening

**Date:** 2026-10-20  
**Repository:** KAVACH-X / SENTINEL-X (`NEATLOG-SENTINAL`)  
**Role:** Senior Full-Stack Engineer, Application Security Architect, QA Lead

---

## 1. Executive Summary

The KAVACH-X / SENTINEL-X cybersecurity platform has been stabilized and end-to-end repaired. Real workflows across project onboarding, static scanning, AI remediation planning, exact-patch-hash human approval, isolated Docker verification, cryptographic evidence reporting, and live telemetry tracking have been validated and confirmed operational.

All workflows are powered by the authoritative FastAPI backend (`backend/main.py`), persisted SQLite database (`local-audit/local-server.db`), deterministic patch policy enforcement, exact SHA-256 patch-hash human approval binding, and independent Docker-isolated verification.

---

## 2. Repaired Workflows & Implementation Details

### Step 1: Project Intake & Safe Extraction Repair
- **Safe ZIP Extraction Limits:** Upgraded archive limits in `backend/routes/projects.py` and `backend/middleware.py`:
  - `MAX_FILE`: Increased from 2 MB to 20 MB (allowing modern web assets such as `.webp`, `.png`, fonts, and bundled modules).
  - `MAX_ARCHIVE`: Increased from 10 MB to 50 MB.
  - `MAX_EXTRACTED`: Increased from 32 MB to 150 MB.
  - `MAX_FILES`: Increased from 500 to 2,500 files.
  - Payload limit in middleware: Raised from 12 MB to 64 MB.
  - Fixed false-positive zip-bomb check on empty files (e.g. `__init__.py`).
- **Deterministic Source Tree Digest:** Implemented `compute_source_revision(root: Path) -> str` in `backend/routes/projects.py` calculating a deterministic SHA-256 tree digest across all project files.
- **Upload Deduplication & Idempotency:** Prevented duplicate `CREATED` records from accumulating. If an unuploaded project draft exists with the same name, it is reused. Added a 1-click **"Clean drafts"** utility button on the Projects page.

### Step 2: Authentication & Cross-Origin Session Persistence
- **Same-Origin Vite Proxy:** Configured Vite proxy in `frontend/vite.config.ts` for `/api`, `/health`, and `/ready` to `http://127.0.0.1:8000`.
- **Relative Client Paths:** Updated `frontend/src/api/client.ts` to use same-origin relative URLs in the browser. This eliminates cross-site cookie blocking between `localhost` and `127.0.0.1` (`SameSite=Lax`), preventing the repeated session expiration popup.
- **Operator Session Hardening:** Updated `frontend/src/components/OperatorSession.tsx` to default to "Sign In" mode when sessions expire, cache the operator email in browser storage, and prevent dialog loops.

### Step 3: Minimalist "Security Core" Loading Animation
- **3-Layer Glass Isometric Core:** Implemented `SecurityCore.tsx` and `BootScreen.module.css` with 3 floating geometric glass layers, a central glowing lime shield (`#B7F36B`), a thin sweeping laser scan line, and an orbital track.
- **Real Readiness Lifecycle:** Probes `/health` for backend connectivity and `/ready` for database, verifier, and configuration state without fake timers.
- **Non-Blocking Auto-Advance:** Once system checks complete, automatically transitions to the workspace after 1.2s even when optional dependencies have warnings. Provides an instant `Skip Intro (Esc)` shortcut and `Proceed to Workspace →` button.

### Step 4: Two-Column Security Investigation Workspace
- **Ergonomic Layout:** Updated `frontend/src/pages/Investigation.tsx` and `frontend/src/index.css` with `.investigation-grid`:
  - **Left Rail (65%):** Code Inspection (diff & source views with line additions/deletions), Isolated Docker Test Evidence (4-column metric grid), and Version/Run History.
  - **Sticky Right Rail (35%):** Exact Canonical Hash Approval panel (`approve`/`reject` buttons with SHA-256 copy shortcut), AI Root Cause Analysis, Cryptographic Attestation summary, and vertical Audit Trail Timeline.
- **Top Metrics Bar (`.investigation-summary`):** 6-tile status strip summarizing Vulnerability type, Severity badge, Affected file, Attempt counter, Target App, and Source revision.

### Step 5: Agent Activity & Command Center Realization
- **Agent Activity (`Activity.tsx`):** Queries real persisted jobs via `api.jobs(50, 0)`, supports deep-linking (`?jobId=...`), and renders live lifecycle events from the SQLite audit ledger via `GET /api/jobs/{id}/events`.
- **Command Center (`Dashboard.tsx`):** Pulls authoritative telemetry from `/api/projects`, `/api/scans`, `/api/scan-findings`, `/api/jobs`, and `/ready`.

### Step 6: Verification Matrix & Evidence Persistence
- **Verification Matrix (`Verification.tsx`):** Displays real test suite executions, individual test assertion outcomes, execution durations, and canonical patch hashes.
- **Evidence Reports (`Evidence.tsx`):** Features interactive case selection and 1-click authentic backend evidence JSON export (`GET /api/jobs/{id}/evidence`).

### Step 7: Independent Red Team Adversarial Verification Engine
- **Profile-Defined Attack Scenarios (`verification/scenarios.py`):**
  - Implemented independently maintained security scenarios for BOLA authorization:
    1. *Document Owner Access:* Legitimate access verification (`BOLA-OWNER-001`, `BOLA-OWNER-002`, `BOLA-OWNER-003`).
    2. *Cross-Tenant Access Denial:* Rigorous denial of cross-tenant reads across all fixture users (`BOLA-CROSS-001` through `BOLA-CROSS-005`).
    3. *Manipulated Document Identifiers:* Path traversal (`../doc_bob_1`), SQL injection strings (`doc_bob_1' OR '1'='1`), null byte insertion (`\x00`), relative dot segments (`doc_alice_1/../doc_bob_1`), and non-string type boundary handling (`BOLA-MANIP-*`).
    4. *Nonexistent Documents:* Standard 404 lookup error preservation (`BOLA-NONEXIST-001`, `BOLA-NONEXIST-002`).
    5. *Missing / Invalid Identity:* Anonymous access denial for `None`, empty string `""`, whitespace, and wildcard token forging (`BOLA-IDENT-*`).
    6. *Boundary Conditions:* Unicode zero-width space variations, case sensitivity, and 1,024-character maximum length identifiers (`BOLA-BOUND-*`).
    7. *Legitimate Functional Integrity:* Metadata fidelity, `is_private` confidentiality, and multi-read stability (`BOLA-LEGIT-METADATA`).
- **Separation of Test Sources (`TestSource` Enum):**
  - Clear classification across `PROTECTED_TEST`, `REGRESSION_TEST`, `ADVERSARIAL_SCENARIO`, and `AI_SUGGESTED_TEST`.
  - Untrusted AI-suggested tests are strictly bounded in count and string length, categorized as `AI_SUGGESTED_TEST`, and assigned `is_mandatory=False`. Failures in optional AI-suggested tests do NOT fail mandatory verification.
- **6-Status Verdict Classification Engine (`TestResultEvaluator`):**
  - Evaluator distinguishes:
    - `VERIFIED`: all mandatory checks and integrity checks passed.
    - `VERIFICATION_FAILED`: a required security or regression property failed.
    - `EXECUTION_ERROR`: reliable execution could not complete (crash, timeout, container failure).
    - `INCONCLUSIVE`: evidence is missing or contradictory (counts mismatch individual records, stdout contradiction, missing/tampered HMAC attestation).
    - `UNSUPPORTED`: the vulnerability is outside the supported profile.
    - `POLICY_REJECTED`: the candidate violates an enforced policy.
- **Adversarial Verification Reporting (`frontend/src/pages/Verification.tsx` & `VerificationPanel.tsx`):**
  - Renders attack scenarios attempted/passed/failed, regression suite counts, baseline exploitation proof, suite version, scenario matrix breakdown, and explicit evaluation limitations.
  - Features prominent security disclaimer: *"Adversarial verification confirms mitigation against evaluated threat vectors within bounded sandbox constraints. It does not certify absence of other vulnerabilities or prove global system correctness."*
- **Key Acceptance Test Passed (`test_redteam_engine.py`):**
  - Confirmed that a deliberately superficial BOLA fix (`incomplete_patch.diff` that only checks `user == "alice" and doc == "doc_bob_1"`) is categorically rejected (`VERIFICATION_FAILED`) by the independently maintained cross-tenant matrix test.

---

## 3. Key Files Modified / Created

| File | Change |
| :--- | :--- |
| `verification/scenarios.py` | Independent Red Team scenario definitions, safe AI test validation, and scenario runner engine. |
| `verification/contracts.py` | Added `INCONCLUSIVE`, `UNSUPPORTED` verdicts, `TestSource` enum, `AdversarialScenario`, `AdversarialReport`. |
| `verification/evaluator.py` | Implemented 6-verdict classification engine, optional test failure handling, and adversarial report parsing. |
| `verification/adapter.py` | Integrated adversarial report pass-through and strict verdict status mapping. |
| `verification/protected_tests/test_adversarial.py` | Immutable protected Red Team adversarial test suite. |
| `verification/protected_tests/conftest.py` | Attached detailed adversarial report into test report JSON payload. |
| `verification/tests/test_redteam_engine.py` | 12 comprehensive unit and regression tests including Key Acceptance Test. |
| `backend/schemas.py` | Added optional `adversarial_report` field to `VerificationResult`. |
| `backend/routes/projects.py` | Modernized upload limits, fixed zip-bomb false positives, and deterministic source revision. |
| `backend/middleware.py` | Raised request body limit for project uploads from 12 MB to 64 MB. |
| `frontend/vite.config.ts` | Configured same-origin proxy for `/api`, `/health`, `/ready` to eliminate cross-origin cookie drops. |
| `frontend/src/api/types.ts` | Added `AdversarialScenario` and `AdversarialReport` TypeScript types. |
| `frontend/src/components/VerificationPanel.tsx` | Added Red Team Adversarial Verification cards, scenario breakdown, and disclaimer. |
| `frontend/src/pages/Verification.tsx` | Added expandable Red Team Adversarial Verification Matrix. |

---

## 5. Controlled Mutation Testing and Test Quality Engine

### Architectural Foundations
- **Disposable Fixture Safety:** Operates strictly on ephemeral in-memory copies (`MutationRunner.compile_mutant`); host source files, repository git trees, and protected test assets are never altered or touched.
- **Whitelisted Mutation Operators:**
  1. `BYPASS_OWNERSHIP_CHECK`: Injects constant `if False:` in place of object-level authorization checks.
  2. `REVERSE_AUTHORIZATION_CONDITION`: Inverts identity comparison (`!=` to `==`), locking out legitimate owners and permitting adversaries.
  3. `ALTER_UNAUTHORIZED_RESPONSE`: Returns empty `dict` instead of raising expected 403 `PermissionError`.
  4. `REMOVE_IDENTITY_CHECK`: Bypasses anonymous / empty identity validation.
  5. `CONDITIONAL_LOGIC_ERROR`: Simulates superficial patches by only protecting specific resources (e.g. `doc_bob_1`).
  6. `UNTESTED_HYPOTHETICAL_WEAKNESS`: Injects an unasserted backdoor admin principal (`untested_qa_backdoor_admin`) to prove that surviving mutants expose genuine test suite gaps.
  7. `INVALID_SYNTAX_MUTATION`: Injects intentional compilation/syntax errors to verify that non-viable mutants are excluded from the score.
- **Strict 4-Way Outcome Classification:**
  - `KILLED`: A valid protected or adversarial scenario detected the injected flaw.
  - `SURVIVED`: The injected flaw passed undetected through all assertions (identifies a test gap).
  - `INVALID`: Mutant failed AST compilation or syntax parsing (excluded from valid mutant population).
  - `INCONCLUSIVE`: Execution timeout or sandbox infrastructure error (excluded from score, never counted as killed).
- **Mathematical Mutation Score Formula:**
  $$\text{Mutation Score} = \left(\frac{\text{Killed Mutants}}{\text{Killed Mutants} + \text{Surviving Mutants}}\right) \times 100$$
  Formula strictly operates on valid testable mutants (`5 / 6 * 100 = 83.33%`). Invalid and inconclusive mutants are excluded from the denominator.
- **Workflow & Persistence Guarantees:**
  - Mutation testing executes safely alongside verification.
  - On-demand mutation testing via `POST /api/jobs/{job_id}/mutation-test` emits audit events and embeds results into run records without overwriting or weakening the authoritative `VERIFIED` status of approved patches.
- **Frontend Test Quality UI:**
  - Dedicated **Test Quality & Mutation Resilience** card in `VerificationPanel.tsx` and `Verification.tsx`.
  - Displays score gauge, calculation formula, valid/killed/surviving/invalid pills, whitelisted mutant table, killing test scenarios, missing test weaknesses, and explicit test rigor disclaimer.

### Test Acceptance Results (`test_mutation_engine.py`)
- Baseline trusted tests pass cleanly (100% mitigation on baseline).
- Security-breaking mutations (`MUTANT-001` through `MUTANT-005`) reliably detected and `KILLED`.
- Untested weakness (`MUTANT-006`) correctly reported as `SURVIVED` test weakness.
- Syntax-corrupted mutant (`MUTANT-007`) correctly excluded as `INVALID`.
- Inconclusive infrastructure faults cannot artificially improve the mutation score.
- Triple-run test validates 100% determinism and reproducibility.

---

## 7. Step 9: Evidence Integrity & Cryptographic Verification Attestation

### A. Authoritative Evidence Contract (`sentinel-attestation-v1`)
To ensure verification reports are reproducible and independently auditable without relying on frontend state, blockchain, or secondary databases, an immutable canonical attestation contract was designed (`backend/attestation.py`):

1. **Identity & Provenance:**
   - `run_id`: Unique verification execution identifier.
   - `project_id` & `job_id`: Target project and remediation job identifiers.
   - `source_revision` & `source_digest`: Exact Git commit / directory tree SHA-256 digest before patch application.
   - `patch_hash`: Exact SHA-256 digest of approved patch bytes.
   - `patch_attempt`: Numerical attempt counter.
   - `approved_by` & `approved_at`: Authenticated human reviewer and RFC 3339 timestamp.
2. **Environment & Suite Specification:**
   - `test_suite_id` & `test_suite_version`: Identifier and deterministic hash/version of the protected test suite (`bola-protected-tests-v1`).
   - `verifier_version`: Exact version of the isolated verification engine (`sentinel-verifier-v1`).
   - `container_image_digest`: Container image digest (`sha256:...`) or isolated execution indicator.
   - `execution_config`: Relevant environment variables, timeouts, resource limits, and Python environment settings.
3. **Execution Outcomes & Test Reconciliation:**
   - `test_results`: Exact array of individual test execution outcomes (`name`, `outcome`, `duration_ms`).
   - `tests_summary`: Fully reconciled record containing `total`, `passed`, `failed`, `exit_status`, `timed_out`, and `infrastructure_status`.
   - `verdict`: Evaluator verdict (`VERIFIED` or `VERIFICATION_FAILED`).
4. **Canonical RFC 8785 Digest:**
   - `canonical_digest`: SHA-256 computed over the canonically formatted JSON payload according to RFC 8785 (deterministic key ordering, strict UTF-8 formatting, zero whitespace variances).
5. **Privacy & Security Boundaries:**
   - Zero secrets, zero access tokens, zero API keys, and zero unneeded personal information are included in the payload.

### B. Multi-Vector Consistency Reconciliation
Before an attestation is certified or verified, the engine executes strict multi-point consistency checks:
- **Patch Hash Recomputation:** Recomputes the SHA-256 hash over raw patch bytes and matches it against `approved_patch_hash`.
- **Source Revision & Digest Verification:** Confirms source tree revision matches the approved target and recomputes the tree digest.
- **Approval Binding Validation:** Confirms the patch was actively approved by an authorized operator specifically for this patch hash and attempt.
- **Test Suite Identity Verification:** Validates `test_suite_id` matches the authorized verification profile.
- **Test Record Reconciliation:** Reconciles every individual test result in `test_results` against `tests_summary` (counts of passed and failed must match exactly, and sum must equal `tests_total`).
- **Execution Completion Validation:** Rejects runs marked interrupted, timed out, or incomplete.
- **Contradictory / Malformed Evidence Rejection:** Any missing required field, unsupported schema version, or contradictory status immediately fails validation.

### C. Protected Ed25519 Asymmetric Digital Signatures
- **Protected Signing Key:** Private keys are stored strictly in `backend/keys/` on the protected host filesystem, outside uploaded project trees and verification containers.
- **Established Cryptography:** Utilizes the industry-standard `cryptography` Python library (`cryptography.hazmat.primitives.asymmetric.ed25519`).
- **Key Registry & Rotation:** Supports key identifiers (e.g. `sentinel-key-2026-v1`) and public key registries allowing seamless key rotation without invalidating historical signatures.
- **Honest Signature Claims:** Unsigned digests are NEVER labeled as digital signatures (`signature_valid: false` if signature missing or algorithm none).
- **Honest Timestamp Claims:** Explicitly flags `trusted_timestamp: false` because timestamps are host-generated and not anchored to an external RFC 3161 TSA server.

### D. Export, Offline Inspection & UI
- **Zero Frontend Dependency:** Verifiers can inspect attestations via:
  - `GET /api/jobs/{job_id}/attestation`: Full signed attestation JSON export.
  - `POST /api/attestation/verify`: Public offline verification endpoint (bypasses auth session cookies).
- **Database Persistence:** Evidence and attestation payload are persisted in SQLite `run_attestations` BEFORE reporting completion to the client.
- **Frontend Attestation Inspector (`Evidence.tsx`):**
  - Displays Ed25519 signature seal, Key ID, algorithm, canonical digest, and test reconciliation.
  - "Verify Cryptographic Seal" button runs live validation.
  - "Export Attestation JSON" button downloads RFC 8785 signed JSON artifact.
  - Interactive "Auditor Verification Sandbox" allowing auditors to paste and verify arbitrary/tampered attestations.

### E. Tampering Acceptance Test Suite (`test_evidence_attestation.py`)
All 12 tampering and integrity scenarios were tested and verified:
1. `test_valid_attestation_passes_validation`: Legitimate signed attestation passes all checks.
2. `test_tampered_patch_bytes_detected`: Changing patch bytes triggers patch hash mismatch failure.
3. `test_tampered_source_digest_detected`: Changing source digest triggers source mismatch failure.
4. `test_altered_test_outcomes_detected`: Changing test outcome triggers test reconciliation failure.
5. `test_missing_tests_detected`: Truncating individual tests triggers count reconciliation failure.
6. `test_modified_approval_records_detected`: Modifying approving user/timestamp breaks approval binding.
7. `test_invalid_digital_signature_detected`: Altering even 1 byte in the signature triggers Ed25519 invalid signature failure.
8. `test_unsupported_schema_version_detected`: Fails on unsupported schema versions.
9. `test_wrong_verification_run_detected`: Replaying attestation to a different run ID is rejected.
10. `test_cryptographic_key_rotation_support`: Keys rotate cleanly across versions (`v1` to `v2`).
11. `test_claims_and_limitations_documented`: Attestation payload explicitly embeds `WHAT_IT_PROVES` and `WHAT_IT_DOES_NOT_PROVE`.
12. `test_offline_api_endpoints`: Public endpoint verifies attestations without session cookies.

---

## 8. What The Attestation Proves vs. What It Does NOT Prove

| What The Attestation Proves | What The Attestation Does NOT Prove |
|:---|:---|
| The exact patch bytes match the approved SHA-256 hash. | Does NOT prove the entire application or repository is bug-free. |
| The source code tree matches the recorded SHA-256 digest. | Does NOT prove that the test suite itself was bug-free or comprehensive. |
| The run was authorized by a specific operator before execution. | Does NOT prove trusted time without an external RFC 3161 TSA server. |
| Individual test records reconcile exactly with summary counts. | A SHA-256 digest only proves relationship when compared to known bytes. |
| The canonical RFC 8785 payload was signed with private key `sentinel-key-2026-v1`. | Does NOT prove that the verifier container environment was uncompromised. |

---

## 9. Step 10: AI-Agnostic Patch Intake and Comparison Lab

### A. Architecture & Workflow Design
SENTINEL-X was extended to support candidate patches authored by external AI tools (e.g., Claude 3.7 Sonnet, Cursor / Claude-3.5, GitHub Copilot, DeepSeek-R1) or manual development without replacing or disabling the internal Ollama agent.

1. **Intake Engine (`backend/candidates.py` & `backend/routes/candidates.py`):**
   - Endpoints: `POST /api/patches/intake`, `POST /api/jobs/{job_id}/candidates`, `GET /api/candidates`, `GET /api/candidates/compare`.
   - Authoritative Hash Recomputation: The backend parses raw patch bytes and recomputes the SHA-256 digest (`patch_hash()`). Client-supplied hashes are **never trusted**.
   - Target Source Revision Validation: Current workspace source revision is recomputed via `TARGET_MANIFEST.source_revision(...)`. Any candidate claiming a stale or non-matching revision is rejected with `STALE_SOURCE_REVISION` (409 Conflict).
   - Strict Policy Enforcement: Validates against `validate_patch` (hunk lines, declared file matches, byte boundaries) and `PatchValidator` (AST scanning, forbidden syscalls).
   - Authoring Source Association: Accurately records authoring tool metadata in `patch_proposals.authoring_source` and `candidate_patches` index.

2. **Equal Approval & Isolation Rules:**
   - **No Privilege by Claimed Origin:** Every external patch is placed in `AWAITING_APPROVAL` (or `POLICY_REJECTED`). No candidate can bypass human approval because it was generated by a popular or prestigious AI tool.
   - **Exact Hash Human Approval:** The human operator must explicitly approve via `POST /api/jobs/{job_id}/approval` binding the exact SHA-256 patch hash.
   - **Restricted Sandbox Execution:** Verification runs strictly inside isolated execution environments with resource bounds.

3. **Multi-Candidate Side-by-Side Comparison:**
   - Normalizes test suites and execution parameters.
   - Detects discrepancies: Flags `source_revision_mismatch: true` if candidates were evaluated against different Git trees; flags test profile differences.
   - Displays side-by-side metrics: policy verdict, patch byte size, additions/deletions, files changed, mandatory scenario outcomes, regression outcomes, adversarial attack results, execution duration, and cryptographic evidence attestation validity.
   - **Scientific Fairness Guarantee:** Excludes unexplained or arbitrary composite scores. Returns strictly factual technical data.

4. **Unsupported Patch Formats (Strictly Rejected & Documented):**
   - **Windows CRLF line endings (`\r\n`):** Rejected with `UNSUPPORTED_PATCH_ENCODING` (UNIX newlines required).
   - **Binary patches (`GIT binary patch`):** Rejected with `UNSUPPORTED_PATCH_FORMAT`.
   - **Non-unified diffs:** Normal diffs, context diffs (`*** / ---`), and raw file replacements missing standard `diff --git ` headers are rejected with `MALFORMED_DIFF`.
   - **Prohibited Git operations:** File renames, deletions, creations, mode changes (`new file mode`, `deleted file mode`, `rename to`) are rejected with `PROHIBITED_PATCH_OPERATION`.
   - **Protected file edits:** Modifying files outside the authorized target (e.g. `verification/protected_tests/`, `Dockerfile`) is rejected with policy violation.

### B. Frontend Patch Lab UI (`frontend/src/pages/PatchLab.tsx`)
- Available at `/lab` route and in sidebar navigation under "OPERATIONS".
- Interactive intake modal with presets for Claude, Cursor, Copilot, DeepSeek, and Manual.
- Active candidate table with status badges and quick 1-click Approve / Verify actions.
- Multi-candidate comparison matrix rendering normalized side-by-side evaluation columns with discrepancy alerts.

### C. Acceptance Test Results (`test_patch_intake_and_comparison.py`)
All 12 acceptance tests pass cleanly:
1. `test_patch_intake_from_different_authoring_sources`: Claude, Cursor, Manual patches accepted independently.
2. `test_behavior_over_claimed_origin_and_adversarial_outcome`: Valid fix vs broken fix claiming the same prestigious model evaluated purely on actual behavior.
3. `test_client_supplied_patch_hash_is_never_trusted`: Spoofed client hashes ignored; authoritative SHA-256 recomputed.
4. `test_intake_rejects_malformed_diffs`: Plain text and bad hunk counts rejected.
5. `test_intake_rejects_unauthorized_and_protected_file_changes`: Protected test changes rejected.
6. `test_intake_rejects_stale_source_revision`: Outdated source revisions rejected with 409.
7. `test_all_external_sources_require_human_approval`: Verification blocked before human approval.
8. `test_rejected_approval_prevents_verification`: Operator rejection halts verification.
9. `test_unsupported_patch_formats_rejected`: Binary, CRLF, and rename operations rejected.
10. `test_patch_comparison_normalizes_and_detects_discrepancies`: Side-by-side comparison normalizes execution without composite score.
11. `test_candidate_results_never_cross_contaminate`: Isolated evidence records between candidates.
12. `test_duplicate_intake_requests_create_distinct_trackable_candidates`: Separate trackable records for duplicate diff submissions.

---

## 10. Repository-Wide Test & Build Verification

* **Total Automated Tests:** **270 PASSED**, 2 skipped, 12 deselected, 0 failures across repository.
* **Frontend Production Build:** Built cleanly with Vite v6 (`npm run build`) in 6.26s with 0 TypeScript/CSS errors.
