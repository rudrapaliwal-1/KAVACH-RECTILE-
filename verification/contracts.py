"""Data contracts and schemas for SENTINEL-X Verification (Developer 3).

Coordinated with Dev 1 (FastAPI Orchestrator) and Dev 4 (LLM Reflection Module).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union, Awaitable


class VerificationStatus(str, Enum):
    """Evaluation status emitted by Layer 5 Verification."""
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    POLICY_REJECTED = "POLICY_REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class TestSource(str, Enum):
    """Source classification for verification checks."""
    __test__ = False
    PROTECTED_TEST = "PROTECTED_TEST"             # 1. Authoritative protected tests maintained by verifier
    REGRESSION_TEST = "REGRESSION_TEST"           # 2. Existing application regression tests
    ADVERSARIAL_SCENARIO = "ADVERSARIAL_SCENARIO" # 3. Additional adversarial scenarios generated from validated profiles
    AI_SUGGESTED_TEST = "AI_SUGGESTED_TEST"       # 4. Optional AI-suggested tests (untrusted until validated)


# Callable accepting (patch_hash: str, approval_id: str) -> bool
ApprovalVerifier = Union[
    Callable[[str, str], bool],
    Callable[[str, str], Awaitable[bool]],
]


@dataclass
class _BaseModel:
    """Provides dictionary and JSON serialization helpers."""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return self._serialize(data)

    def _serialize(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._serialize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._serialize(item) for item in obj]
        if isinstance(obj, Enum):
            return obj.value
        return obj


@dataclass
class AdversarialScenario(_BaseModel):
    """Structured record for an independently evaluated security scenario."""
    scenario_id: str
    security_property: str
    test_source: str
    preconditions: Dict[str, Any]
    expected_behavior: str
    actual_result: Optional[str] = None
    execution_status: str = "pending"  # passed, failed, error, skipped
    explanation: str = ""
    is_mandatory: bool = True


@dataclass
class AdversarialReport(_BaseModel):
    """Comprehensive Red Team adversarial verification report."""
    attack_scenarios_attempted: int = 0
    attack_scenarios_passed: int = 0
    attack_scenarios_failed: int = 0
    regression_scenarios_total: int = 0
    regression_scenarios_passed: int = 0
    regression_scenarios_failed: int = 0
    execution_errors: List[str] = field(default_factory=list)
    vulnerability_reproduced_on_baseline: bool = True
    vulnerability_mitigated: bool = False
    protected_suite_version: str = "bola-redteam-v1"
    patch_hash: str = ""
    source_revision: str = ""
    scenarios: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    disclaimer: str = (
        "Adversarial verification confirms mitigation against evaluated threat vectors "
        "within bounded sandbox constraints. It does not certify absence of other vulnerabilities "
        "or prove global system correctness."
    )


class MutantStatus(str, Enum):
    """Classification of mutant execution outcomes."""
    KILLED = "KILLED"             # Detected by protected tests
    SURVIVED = "SURVIVED"         # Tests failed to detect defect (test weakness)
    INVALID = "INVALID"           # Unviable/syntactically broken variant (excluded from score)
    INCONCLUSIVE = "INCONCLUSIVE" # Infrastructure or execution error (excluded from score)


class MutationOperator(str, Enum):
    """Controlled mutation operators whitelist."""
    BYPASS_OWNERSHIP_CHECK = "BYPASS_OWNERSHIP_CHECK"
    REVERSE_AUTHORIZATION_CONDITION = "REVERSE_AUTHORIZATION_CONDITION"
    ALTER_UNAUTHORIZED_RESPONSE = "ALTER_UNAUTHORIZED_RESPONSE"
    REMOVE_IDENTITY_CHECK = "REMOVE_IDENTITY_CHECK"
    CONDITIONAL_LOGIC_ERROR = "CONDITIONAL_LOGIC_ERROR"
    UNTESTED_HYPOTHETICAL_WEAKNESS = "UNTESTED_HYPOTHETICAL_WEAKNESS"
    INVALID_SYNTAX_MUTATION = "INVALID_SYNTAX_MUTATION"


@dataclass
class MutantRecord(_BaseModel):
    """Record of an individual evaluated mutant."""
    mutant_id: str
    operator: str
    description: str
    mutant_hash: str
    status: str  # KILLED, SURVIVED, INVALID, INCONCLUSIVE
    killing_test: Optional[str] = None
    execution_output: Optional[str] = None
    exclusion_reason: Optional[str] = None


@dataclass
class MutationReport(_BaseModel):
    """Summary and evaluation of test suite quality via mutation testing."""
    total_mutants: int = 0
    valid_mutants: int = 0
    killed_mutants: int = 0
    surviving_mutants: int = 0
    invalid_mutants: int = 0
    inconclusive_mutants: int = 0
    mutation_score: float = 0.0
    calculation_formula: str = "(Killed / (Killed + Surviving)) * 100"
    test_suite_version: str = "bola-redteam-v1"
    source_revision: str = ""
    duration_ms: int = 0
    mutants: List[Dict[str, Any]] = field(default_factory=list)
    surviving_mutant_weaknesses: List[str] = field(default_factory=list)
    disclaimer: str = (
        "Mutation testing measures the defect-detection capability of the test suite against "
        "controlled synthetic faults. It represents test-suite rigor and completeness, not an "
        "overall application security certification."
    )


@dataclass
class VerificationRequest(_BaseModel):
    """Payload provided by Dev 1 Orchestrator to request patch verification."""
    job_id: str
    target_app_id: str = "bola-demo-v1"
    patch_text: str = ""
    patch_hash: str = ""
    approval_id: str = ""
    patch_id: str = ""
    source_revision: str = ""
    verification_profile: str = ""
    run_id: str = ""
    attempt: int = 0
    timeout_seconds: int = 30
    source_root: Optional[str] = None


@dataclass
class VerificationResult(_BaseModel):
    """Structured verdict output returned to Dev 1 Orchestrator."""
    job_id: str
    patch_hash: str
    status: str  # VERIFIED, VERIFICATION_FAILED, EXECUTION_ERROR, POLICY_REJECTED, INCONCLUSIVE, UNSUPPORTED
    tests_total: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    failed_tests: List[str] = field(default_factory=list)
    test_results: List[Dict[str, str]] = field(default_factory=list)
    duration_ms: int = 0
    execution_error: Optional[str] = None
    run_id: Optional[str] = None
    patch_id: Optional[str] = None
    test_suite_id: Optional[str] = None
    tests_collected: Optional[int] = None
    collection_complete: Optional[bool] = None
    execution_completed: Optional[bool] = None
    adversarial_report: Optional[Dict[str, Any]] = None
    verdict_category: Optional[str] = None
    mutation_report: Optional[Dict[str, Any]] = None

