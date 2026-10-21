"""Controlled Mutation Testing and Test Quality Engine (Layer 5 / Red Team).

Safely generates and executes synthetically defected copies of trusted target
code to measure the defect-detection capability and resilience of protected tests.

Key Principles:
- Controlled source fixtures: operates strictly on ephemeral in-memory copies.
  Never modifies the original project, protected tests, or host files.
- Whitelist of mutation operators for authorization/BOLA vulnerabilities.
- Strict classification:
  * KILLED: A valid test detected the defect.
  * SURVIVED: Tests failed to detect the defect (identifies test suite weakness).
  * INVALID: Syntax/compilation failure before test execution (excluded from score).
  * INCONCLUSIVE: Timeout or execution infrastructure fault (excluded from score).
- Score is calculated ONLY from valid mutants: (Killed / (Killed + Survived)) * 100.
"""

from __future__ import annotations

import ast
import hashlib
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .contracts import (
    MutantRecord,
    MutantStatus,
    MutationOperator,
    MutationReport,
)
from .lab.app.sample_data import DOCUMENTS
from .scenarios import get_profile_scenarios, execute_single_scenario


# Trusted remediated baseline code for BOLA lab
CORRECT_ACCESS_CODE = '''"""Document access control module with BOLA remediation."""

from typing import Any, Dict, Optional
from verification.lab.app.sample_data import DOCUMENTS


def get_document(requesting_user_id: Optional[str], document_id: str) -> Dict[str, Any]:
    """Retrieve document by ID for requesting user with strict object ownership."""
    # Identity check
    if not requesting_user_id or not str(requesting_user_id).strip():
        raise PermissionError("Anonymous access denied: requesting_user_id required")

    # Document existence check
    if document_id not in DOCUMENTS:
        raise LookupError(f"Document '{document_id}' not found")

    doc = DOCUMENTS[document_id]

    # Object-level authorization check
    if doc.get("owner_id") != requesting_user_id:
        raise PermissionError(f"Forbidden: User '{requesting_user_id}' does not own document '{document_id}'")

    return dict(doc)
'''


class MutationGenerator:
    """Deterministic, bounded generator of synthetically mutated code variants."""

    @classmethod
    def generate_mutants(cls, base_code: str = CORRECT_ACCESS_CODE) -> List[Tuple[str, str, str]]:
        """Generate a deterministic list of (operator, description, mutated_code) tuples."""
        mutants: List[Tuple[str, str, str]] = []

        # 1. BYPASS_OWNERSHIP_CHECK: Bypasses the object-level ownership check completely
        bypass_code = base_code.replace(
            'if doc.get("owner_id") != requesting_user_id:',
            'if False:  # MUTANT: Ownership check bypassed',
        )
        mutants.append((
            MutationOperator.BYPASS_OWNERSHIP_CHECK.value,
            "Bypass object-level authorization ownership check with constant False",
            bypass_code,
        ))

        # 2. REVERSE_AUTHORIZATION_CONDITION: Reverses authorization logic (blocks owner, allows attacker)
        reverse_code = base_code.replace(
            'if doc.get("owner_id") != requesting_user_id:',
            'if doc.get("owner_id") == requesting_user_id:  # MUTANT: Condition inverted',
        )
        mutants.append((
            MutationOperator.REVERSE_AUTHORIZATION_CONDITION.value,
            "Invert ownership comparison operator from != to ==",
            reverse_code,
        ))

        # 3. ALTER_UNAUTHORIZED_RESPONSE: Returns empty dictionary instead of raising PermissionError
        alter_resp_code = base_code.replace(
            'raise PermissionError(f"Forbidden: User \'{requesting_user_id}\' does not own document \'{document_id}\'")',
            'return {}  # MUTANT: Return empty dict instead of PermissionError',
        )
        mutants.append((
            MutationOperator.ALTER_UNAUTHORIZED_RESPONSE.value,
            "Alter unauthorized response from raising PermissionError to returning empty dict",
            alter_resp_code,
        ))

        # 4. REMOVE_IDENTITY_CHECK: Bypasses anonymous / empty identity check
        remove_ident_code = base_code.replace(
            'if not requesting_user_id or not str(requesting_user_id).strip():',
            'if False:  # MUTANT: Anonymous check removed',
        )
        mutants.append((
            MutationOperator.REMOVE_IDENTITY_CHECK.value,
            "Remove anonymous user identity validation check",
            remove_ident_code,
        ))

        # 5. CONDITIONAL_LOGIC_ERROR: Superficial fix that only checks single document
        logic_error_code = base_code.replace(
            'if doc.get("owner_id") != requesting_user_id:',
            'if doc.get("owner_id") != requesting_user_id and document_id == "doc_bob_1":  # MUTANT: Single-doc check',
        )
        mutants.append((
            MutationOperator.CONDITIONAL_LOGIC_ERROR.value,
            "Introduce bounded conditional logic error (only protects doc_bob_1)",
            logic_error_code,
        ))

        # 6. UNTESTED_HYPOTHETICAL_WEAKNESS: Injects a backdoor bypass for an unasserted identifier
        # (Demonstrates a surviving mutant that exposes a missing test assertion)
        weakness_code = base_code.replace(
            'doc = DOCUMENTS[document_id]',
            'doc = DOCUMENTS[document_id]\n    if requesting_user_id == "untested_qa_backdoor_admin": return dict(doc)',
        )
        mutants.append((
            MutationOperator.UNTESTED_HYPOTHETICAL_WEAKNESS.value,
            "Inject backdoor bypass for specific untested principal ('untested_qa_backdoor_admin')",
            weakness_code,
        ))

        # 7. INVALID_SYNTAX_MUTATION: Syntactically broken mutant (must be excluded from score calculation)
        invalid_syntax_code = base_code + "\ndef invalid_syntax_mutant(::: broken python\n"
        mutants.append((
            MutationOperator.INVALID_SYNTAX_MUTATION.value,
            "Intentional invalid Python syntax error to test exclusion filtering",
            invalid_syntax_code,
        ))

        return mutants


class MutationRunner:
    """Executes mutants against protected tests and scenario suite in memory."""

    @classmethod
    def compile_mutant(cls, code: str) -> Tuple[Optional[Callable[..., Any]], Optional[str]]:
        """Safely parse and compile mutant code in a clean local namespace."""
        try:
            tree = ast.parse(code)
            compiled = compile(tree, filename="<mutant>", mode="exec")
            local_scope: Dict[str, Any] = {"DOCUMENTS": DOCUMENTS}
            exec(compiled, local_scope)
            fn = local_scope.get("get_document")
            if not callable(fn):
                return None, "Function 'get_document' not found in compiled mutant"
            return fn, None
        except SyntaxError as exc:
            return None, f"SyntaxError in mutant code: {exc}"
        except Exception as exc:
            return None, f"Compilation failed: {type(exc).__name__}: {exc}"

    @classmethod
    def evaluate_mutant(
        cls,
        mutant_id: str,
        operator: str,
        description: str,
        mutated_code: str,
        timeout_seconds: float = 2.0,
    ) -> MutantRecord:
        """Execute a single mutant and classify as KILLED, SURVIVED, INVALID, or INCONCLUSIVE."""
        mutant_hash = "sha256:" + hashlib.sha256(mutated_code.encode("utf-8")).hexdigest()

        # Step 1: Compilation Check (Detect INVALID mutants)
        fn, compile_err = cls.compile_mutant(mutated_code)
        if compile_err:
            return MutantRecord(
                mutant_id=mutant_id,
                operator=operator,
                description=description,
                mutant_hash=mutant_hash,
                status=MutantStatus.INVALID.value,
                exclusion_reason=f"Compilation failed (non-viable mutant): {compile_err}",
            )

        # Step 2: Execute Protected & Adversarial Scenarios
        scenarios = get_profile_scenarios("bola-required-tests-v1")
        killing_test: Optional[str] = None
        start_time = time.perf_counter()

        try:
            for sc in scenarios:
                if time.perf_counter() - start_time >= timeout_seconds:
                    return MutantRecord(
                        mutant_id=mutant_id,
                        operator=operator,
                        description=description,
                        mutant_hash=mutant_hash,
                        status=MutantStatus.INCONCLUSIVE.value,
                        exclusion_reason=f"Mutant evaluation timed out after {timeout_seconds}s",
                    )

                res = execute_single_scenario(sc, fn)
                if res.execution_status in ("failed", "error"):
                    # The test caught the defect -> Mutant is KILLED!
                    killing_test = f"{sc.scenario_id} ({sc.security_property})"
                    break

        except Exception as exc:
            return MutantRecord(
                mutant_id=mutant_id,
                operator=operator,
                description=description,
                mutant_hash=mutant_hash,
                status=MutantStatus.INCONCLUSIVE.value,
                exclusion_reason=f"Execution error in sandbox runner: {exc}",
            )

        if killing_test:
            return MutantRecord(
                mutant_id=mutant_id,
                operator=operator,
                description=description,
                mutant_hash=mutant_hash,
                status=MutantStatus.KILLED.value,
                killing_test=killing_test,
                execution_output=f"Detected by test scenario: {killing_test}",
            )
        else:
            return MutantRecord(
                mutant_id=mutant_id,
                operator=operator,
                description=description,
                mutant_hash=mutant_hash,
                status=MutantStatus.SURVIVED.value,
                execution_output="All test assertions passed despite injected defect.",
            )

    @classmethod
    def run_mutation_suite(
        cls,
        base_code: str = CORRECT_ACCESS_CODE,
        source_revision: str = "",
        custom_mutants: Optional[List[Tuple[str, str, str]]] = None,
        timeout_per_mutant: float = 2.0,
    ) -> MutationReport:
        """Execute full controlled mutation testing suite and generate MutationReport."""
        start_time = time.time()
        mutant_defs = custom_mutants if custom_mutants is not None else MutationGenerator.generate_mutants(base_code)

        mutant_records: List[MutantRecord] = []
        killed_count = 0
        survived_count = 0
        invalid_count = 0
        inconclusive_count = 0
        weaknesses: List[str] = []

        for idx, (op, desc, code) in enumerate(mutant_defs):
            m_id = f"MUTANT-{idx+1:03d}"
            record = cls.evaluate_mutant(m_id, op, desc, code, timeout_seconds=timeout_per_mutant)
            mutant_records.append(record)

            if record.status == MutantStatus.KILLED.value:
                killed_count += 1
            elif record.status == MutantStatus.SURVIVED.value:
                survived_count += 1
                weaknesses.append(
                    f"Mutant {record.mutant_id} [{record.operator}] survived: {record.description}"
                )
            elif record.status == MutantStatus.INVALID.value:
                invalid_count += 1
            elif record.status == MutantStatus.INCONCLUSIVE.value:
                inconclusive_count += 1

        total_mutants = len(mutant_records)
        valid_mutants = killed_count + survived_count

        # Score calculation strictly from valid mutants
        if valid_mutants > 0:
            mutation_score = round((killed_count / valid_mutants) * 100, 2)
        else:
            mutation_score = 0.0

        duration_ms = int((time.time() - start_time) * 1000)

        return MutationReport(
            total_mutants=total_mutants,
            valid_mutants=valid_mutants,
            killed_mutants=killed_count,
            surviving_mutants=survived_count,
            invalid_mutants=invalid_count,
            inconclusive_mutants=inconclusive_count,
            mutation_score=mutation_score,
            calculation_formula="(Killed / (Killed + Surviving)) * 100",
            test_suite_version="bola-redteam-v1",
            source_revision=source_revision,
            duration_ms=duration_ms,
            mutants=[m.to_dict() for m in mutant_records],
            surviving_mutant_weaknesses=weaknesses,
        )
