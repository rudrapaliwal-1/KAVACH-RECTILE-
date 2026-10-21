"""Strict public API and trusted adapter payloads."""

from typing import Annotated, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Finding(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    type: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z][A-Z0-9_]+$")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    file_path: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=4000)


class FindingRequest(StrictModel):
    target_app_id: str = Field(min_length=1, max_length=80)
    finding: Finding


class FindingResponse(StrictModel):
    job_id: str
    status: str


class ApprovalRequest(StrictModel):
    patch_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision: Literal["APPROVE", "REJECT"]


class AgentProposal(StrictModel):
    root_cause: str = Field(min_length=1, max_length=4000)
    explanation: str = Field(min_length=1, max_length=8000)
    patch_format: Literal["unified_diff"]
    patch_text: str = Field(min_length=1, max_length=32_768)
    files_changed: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(max_length=1)

    @field_validator("patch_text")
    @classmethod
    def require_utf8(cls, text: str) -> str:
        try:
            text.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("patch text must be valid UTF-8") from error
        return text


class VerificationResult(StrictModel):
    status: Literal["PASSED", "FAILED", "EXECUTION_ERROR"]
    tests_total: int = Field(ge=0, le=100_000)
    tests_passed: int = Field(ge=0, le=100_000)
    tests_failed: int = Field(ge=0, le=100_000)
    failed_tests: list[Annotated[str, Field(max_length=256)]] = Field(default_factory=list, max_length=100)
    test_results: list[dict[str, str]] = Field(default_factory=list, max_length=100)
    duration_ms: int = Field(ge=0, le=86_400_000)
    execution_error: str | None = Field(default=None, max_length=500)
    test_suite_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    tests_collected: int | None = Field(default=None, ge=0, le=100_000)
    collection_complete: bool | None = None
    execution_completed: bool | None = None
    run_id: str | None = Field(default=None, pattern=r"^run-[0-9a-f]{32}$")
    patch_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    source_revision: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    verification_profile: str | None = Field(default=None, max_length=128)
    adversarial_report: dict[str, Any] | None = None
    mutation_report: dict[str, Any] | None = None

    def validate_counts(self) -> None:
        if self.tests_passed + self.tests_failed != self.tests_total:
            raise ValueError("verification counts are inconsistent")
        if self.status == "PASSED" and (self.tests_total == 0 or self.tests_failed or self.execution_error
                                        or not self.test_suite_id or self.tests_collected != self.tests_total
                                        or self.collection_complete is not True or self.execution_completed is not True
                                        or not self.run_id or not self.patch_hash or not self.source_revision
                                        or not self.verification_profile):
            raise ValueError("passing verification requires executed tests without failures")
        if self.status == "FAILED" and self.tests_failed == 0:
            raise ValueError("failed verification requires failed tests")


class PatchIntakeRequest(StrictModel):
    target_app_id: str = Field(default="bola-demo-v1", min_length=1, max_length=80)
    project_id: str | None = None
    finding_id: str | None = None
    finding: Finding | None = None
    job_id: str | None = None
    patch_text: str = Field(min_length=1, max_length=65_536)
    authoring_source: str = Field(default="External Developer / Tool", min_length=1, max_length=128)
    root_cause: str = Field(default="External candidate patch submission", max_length=4000)
    explanation: str = Field(default="Candidate patch submitted for independent verification", max_length=8000)
    claimed_source_revision: str | None = None
    claimed_patch_hash: str | None = None


class PatchIntakeResponse(StrictModel):
    job_id: str
    candidate_id: str
    patch_hash: str
    authoring_source: str
    source_revision: str
    policy_status: str
    policy_reasons: list[str]
    status: str
    created_at: str


class CandidateSummary(StrictModel):
    job_id: str
    candidate_id: str
    authoring_source: str
    status: str
    policy_status: str
    policy_reasons: list[str]
    patch_hash: str
    patch_size_bytes: int
    files_changed: list[str]
    additions: int
    deletions: int
    approval_status: str
    approved_by: str | None = None
    approved_at: str | None = None
    source_revision: str
    test_suite_id: str | None = None
    tests_total: int | None = None
    tests_passed: int | None = None
    tests_failed: int | None = None
    duration_ms: int | None = None
    adversarial_mitigated: bool | None = None
    adversarial_summary: dict[str, Any] | None = None
    evidence_integrity: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list)


class ComparisonReport(StrictModel):
    candidates: list[CandidateSummary]
    normalized_source_revision: str | None = None
    source_revision_mismatch: bool = False
    test_suite_discrepancy: bool = False
    fair_comparison_notes: list[str] = Field(default_factory=list)
    disclaimer: str
