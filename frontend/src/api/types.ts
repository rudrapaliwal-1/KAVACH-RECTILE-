export type WorkflowStatus =
  | "FINDING_RECEIVED" | "PLANNING" | "AWAITING_APPROVAL" | "VERIFYING"
  | "VERIFICATION_FAILED" | "VERIFIED" | "POLICY_REJECTED" | "USER_REJECTED"
  | "RETRY_EXHAUSTED" | "EXECUTION_ERROR" | "UNKNOWN";

export interface Finding {
  id: string; type: string; severity: string; file_path: string;
  description: string; status?: WorkflowStatus; created_at?: string;
}

export interface PatchFile {
  file_path: string;
  diff?: string;
  old_content?: string;
  new_content?: string;
  additions?: number;
  deletions?: number;
}

export interface Patch {
  id?: string;
  job_id: string;
  patch_hash: string;
  attempt?: number;
  explanation?: string;
  files?: PatchFile[];
  diff?: string;
  policy_status?: string;
  approval_status?: string;
  root_cause?: string;
  patch_text?: string;
  files_changed?: string[];
  status?: WorkflowStatus;
  policy_details?: { reasons?: string[] };
  hash_integrity?: string;
  created_at?: string;
}

export interface TestOutcome {
  name: string;
  outcome: "passed" | "failed" | "error" | "skipped" | string;
  duration_ms?: number;
}

export interface AdversarialScenario {
  scenario_id: string;
  security_property: string;
  test_source: "PROTECTED_TEST" | "REGRESSION_TEST" | "ADVERSARIAL_SCENARIO" | "AI_SUGGESTED_TEST" | string;
  preconditions: Record<string, unknown>;
  expected_behavior: string;
  actual_result?: string | null;
  execution_status: "passed" | "failed" | "error" | "skipped" | string;
  explanation?: string;
  is_mandatory?: boolean;
}

export interface AdversarialReport {
  attack_scenarios_attempted: number;
  attack_scenarios_passed: number;
  attack_scenarios_failed: number;
  regression_scenarios_total: number;
  regression_scenarios_passed: number;
  regression_scenarios_failed: number;
  execution_errors?: string[];
  vulnerability_reproduced_on_baseline: boolean;
  vulnerability_mitigated: boolean;
  protected_suite_version: string;
  patch_hash?: string;
  source_revision?: string;
  scenarios: AdversarialScenario[];
  limitations: string[];
  disclaimer: string;
}

export interface MutantRecord {
  mutant_id: string;
  operator: string;
  description: string;
  mutant_hash: string;
  status: "KILLED" | "SURVIVED" | "INVALID" | "INCONCLUSIVE" | string;
  killing_test?: string | null;
  execution_output?: string | null;
  exclusion_reason?: string | null;
}

export interface MutationReport {
  total_mutants: number;
  valid_mutants: number;
  killed_mutants: number;
  surviving_mutants: number;
  invalid_mutants: number;
  inconclusive_mutants: number;
  mutation_score: number;
  calculation_formula: string;
  test_suite_version: string;
  source_revision?: string;
  duration_ms: number;
  mutants: MutantRecord[];
  surviving_mutant_weaknesses: string[];
}

export interface VerificationResult {
  job_id: string;
  patch_hash: string;
  status: WorkflowStatus | string;
  tests_total?: number;
  tests_passed?: number;
  tests_failed?: number;
  failed_tests?: string[];
  test_results?: TestOutcome[];
  duration_ms?: number;
  execution_error?: string | null;
  test_suite_id?: string | null;
  tests_collected?: number | null;
  collection_complete?: boolean | null;
  execution_completed?: boolean | null;
  run_id?: string | null;
  source_revision?: string | null;
  verification_profile?: string | null;
  adversarial_report?: AdversarialReport | null;
  mutation_report?: MutationReport | null;
}

export interface Job {
  job_id: string;
  finding?: Finding;
  finding_id?: string;
  status: WorkflowStatus | string;
  created_at?: string;
  updated_at?: string;
  attempt?: number;
  patch_hash?: string;
  summary?: string;
  verification?: VerificationResult;
  verification_running?: boolean;
  [key: string]: unknown;
}

export interface WorkflowEvent {
  timestamp: string;
  event_type: WorkflowStatus | string;
  attempt?: number;
  patch_hash?: string;
  summary?: string;
  details?: unknown;
}

export interface SourceResponse {
  job_id: string;
  file_path: string;
  content: string;
  source_revision: string;
}

export interface EvidenceApproval {
  id: string;
  job_id: string;
  patch_id: string;
  patch_hash: string;
  attempt: number;
  decision: "APPROVE" | "REJECT" | string;
  approved_by: string;
  created_at: string;
  binding?: {
    target_app_id: string;
    source_revision: string;
    identity_kind: string;
  };
}

export interface VerificationRun {
  id: string;
  job_id: string;
  patch_id: string;
  patch_hash: string;
  status: string;
  created_at?: string;
  completed_at?: string;
  result: VerificationResult;
  attestation?: {
    run_id: string;
    attempt: number;
    source_revision: string;
    verification_profile: string;
    test_suite_id: string;
    evidence_digest: string;
  };
  attestation_integrity?: string;
}

export interface Evidence {
  job_id: string;
  finding?: Finding;
  target_app_id?: string;
  target_binding?: {
    source_revision: string;
    verification_profile: string;
  };
  source_revision_current?: boolean;
  status?: string;
  patch_attempts?: Patch[];
  approvals?: EvidenceApproval[];
  verification_runs?: VerificationRun[];
  failure_history?: VerificationRun[];
  integrity_issues?: string[];
  conclusion?: string;
  limitations?: string[];
  [key: string]: unknown;
}

export interface ReadinessCheck {
  status: "ready" | "unavailable";
  action: string;
}

export interface ReadinessResponse {
  status: "ready" | "not_ready";
  checks: Record<string, ReadinessCheck>;
  optional_integrations?: Record<string, string>;
}

export interface AttestationPayload {
  schema_version: string;
  run_id: string;
  project_id?: string | null;
  job_id: string;
  source_revision: string;
  source_digest: string;
  patch_hash: string;
  patch_attempt: number;
  approved_by: string;
  approved_at: string;
  test_suite_id: string;
  test_suite_version: string;
  verifier_version: string;
  container_image_digest: string;
  execution_config: Record<string, unknown>;
  test_results: TestOutcome[];
  tests_summary: {
    total: number;
    passed: number;
    failed: number;
    exit_status: number;
    timed_out: boolean;
    infrastructure_status: string;
  };
  verdict: string;
  created_at: string;
  trusted_timestamp: boolean;
  canonical_digest: string;
  claims_and_limitations: {
    what_it_proves: string[];
    what_it_does_not_prove: string[];
  };
}

export interface SignedAttestation {
  schema_version: string;
  key_id: string;
  signature_algorithm: string;
  signature: string;
  attestation: AttestationPayload;
  verified_at?: string;
  valid?: boolean;
}

export interface AttestationVerificationResult {
  valid: boolean;
  errors: string[];
  warnings?: string[];
  key_id?: string;
  signature_algorithm?: string;
  canonical_digest?: string;
  recomputed_digest?: string;
  verified_at?: string;
  attestation?: AttestationPayload;
}

export interface ApiErrorShape { detail?: string; message?: string; error?: string; }

export interface PatchIntakePayload {
  target_app_id?: string;
  project_id?: string | null;
  finding_id?: string | null;
  job_id?: string | null;
  patch_text: string;
  authoring_source?: string;
  root_cause?: string;
  explanation?: string;
  claimed_source_revision?: string | null;
  claimed_patch_hash?: string | null;
}

export interface PatchIntakeResponse {
  job_id: string;
  candidate_id: string;
  patch_hash: string;
  authoring_source: string;
  source_revision: string;
  policy_status: string;
  policy_reasons: string[];
  status: string;
  created_at: string;
}

export interface CandidateSummary {
  job_id: string;
  candidate_id: string;
  authoring_source: string;
  status: string;
  policy_status: string;
  policy_reasons: string[];
  patch_hash: string;
  patch_size_bytes: number;
  files_changed: string[];
  additions: number;
  deletions: number;
  approval_status: string;
  approved_by?: string | null;
  approved_at?: string | null;
  source_revision: string;
  test_suite_id?: string | null;
  tests_total?: number | null;
  tests_passed?: number | null;
  tests_failed?: number | null;
  duration_ms?: number | null;
  adversarial_mitigated?: boolean | null;
  adversarial_summary?: {
    attack_scenarios_passed: number;
    attack_scenarios_attempted: number;
    regression_scenarios_passed: number;
    regression_scenarios_total: number;
    baseline_exploited: boolean;
  } | null;
  evidence_integrity?: {
    has_attestation: boolean;
    canonical_digest: string;
    signature_present: boolean;
    key_id: string;
  } | null;
  limitations: string[];
}

export interface ComparisonReport {
  candidates: CandidateSummary[];
  normalized_source_revision?: string | null;
  source_revision_mismatch: boolean;
  test_suite_discrepancy: boolean;
  fair_comparison_notes: string[];
  disclaimer: string;
}

export interface CandidatePatch {
  id: string;
  job_id: string;
  project_id?: string | null;
  finding_id: string;
  authoring_source: string;
  patch_format: string;
  patch_hash: string;
  source_revision: string;
  policy_status: string;
  job_status: string;
  patch_text: string;
  root_cause: string;
  explanation: string;
  files_changed: string[];
  created_at: string;
}
