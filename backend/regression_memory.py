"""Regression Memory Engine for SENTINEL-X.

Provides bounded, explainable retrieval of historical failure patterns, trusted test
scenarios, remediation guidance, and verification limitations.

Invariants:
1. Historical memory is advisory context only; it NEVER substitutes for independent
   verification of the current approved patch.
2. Uses the existing SQLite architecture; avoids redundant vector databases.
3. Strict sanitization: no secrets, credentials, tokens, host paths, or raw source logs.
4. Bounded retrieval: capped by record count and byte length to prevent prompt bloat.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

_SECRET_PATTERN = re.compile(
    r"(token|secret|password|auth|key|bearer)[:=]\s*([^\s]+)",
    re.IGNORECASE,
)
_HOST_PATH_PATTERN = re.compile(
    r"(/home/[^/\s]+|/Users/[^/\s]+|[A-Za-z]:\\[^\s]+)\\?",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str = "rmem") -> str:
    return f"{prefix}-{uuid4().hex}"


def sanitize_text(text: str, max_length: int = 800) -> str:
    """Sanitizes text by redacting secrets, masking local paths, and bounding length."""
    if not text:
        return ""
    cleaned = _SECRET_PATTERN.sub(r"\1: [REDACTED]", text)
    cleaned = _HOST_PATH_PATTERN.sub("/workspace", cleaned)
    # Remove control characters
    cleaned = "".join(ch for ch in cleaned if ch.isprintable() or ch in "\n\t")
    return cleaned[:max_length].strip()


@dataclass(frozen=True)
class MemoryRecord:
    id: str
    vulnerability_profile: str
    file_path: str
    failure_pattern: str
    sanitized_explanation: str
    remediation_pattern: str
    trusted_test_scenarios: List[str]
    historical_limitations: str
    created_at: str
    relevance_score: int = 0
    explainability: str = ""

    def to_advisory_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vulnerability_profile": self.vulnerability_profile,
            "target_file": self.file_path,
            "failure_pattern": self.failure_pattern,
            "explanation": self.sanitized_explanation,
            "recommended_remediation": self.remediation_pattern,
            "relevant_scenarios": self.trusted_test_scenarios,
            "historical_limitations": self.historical_limitations,
            "relevance_score": self.relevance_score,
            "selection_rationale": self.explainability,
        }


def record_failure_pattern(
    db: Any,
    vulnerability_profile: str,
    file_path: str,
    failure_pattern: str,
    sanitized_explanation: str,
    remediation_pattern: str,
    trusted_scenarios: List[str],
    historical_limitations: str,
) -> str:
    """Stores a sanitized regression pattern in the authoritative SQLite store."""
    rec_id = _id()
    now = _utc_now()

    clean_profile = sanitize_text(vulnerability_profile, 64)
    clean_path = sanitize_text(file_path, 128)
    clean_pattern = sanitize_text(failure_pattern, 256)
    clean_exp = sanitize_text(sanitized_explanation, 512)
    clean_remed = sanitize_text(remediation_pattern, 512)
    clean_limits = sanitize_text(historical_limitations, 256)
    clean_scenarios = [sanitize_text(s, 64) for s in trusted_scenarios[:10]]

    db.execute(
        """
        INSERT INTO regression_memory (
            id, vulnerability_profile, file_path, failure_pattern,
            sanitized_explanation, remediation_pattern, trusted_test_scenarios_json,
            historical_limitations, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            rec_id,
            clean_profile,
            clean_path,
            clean_pattern,
            clean_exp,
            clean_remed,
            json.dumps(clean_scenarios),
            clean_limits,
            now,
        ),
    )
    return rec_id


def retrieve_relevant_memory(
    db: Any,
    vulnerability_profile: str,
    file_path: str,
    failed_tests: Optional[List[str]] = None,
    limit: int = 3,
) -> List[Dict[str, Any]]:
    """Retrieves relevant regression memory records based on profile, file path, and failed tests.
    
    Returns explainable, score-ranked results strictly bounded to limit items.
    """
    rows = db.execute("SELECT * FROM regression_memory").fetchall()
    if not rows:
        seed_default_memory(db)
        rows = db.execute("SELECT * FROM regression_memory").fetchall()

    norm_profile = (vulnerability_profile or "").strip().lower()
    norm_path = (file_path or "").strip().lower()
    failed_set = {t.strip().lower() for t in (failed_tests or [])}

    scored: List[MemoryRecord] = []

    for r in rows:
        score = 0
        rationales: List[str] = []

        rec_profile = str(r["vulnerability_profile"]).strip().lower()
        rec_path = str(r["file_path"]).strip().lower()
        rec_pattern = str(r["failure_pattern"]).strip().lower()

        try:
            scenarios = json.loads(r["trusted_test_scenarios_json"])
        except Exception:
            scenarios = []

        # 1. Profile Match (+50)
        if norm_profile and (norm_profile in rec_profile or rec_profile in norm_profile):
            score += 50
            rationales.append(f"Vulnerability profile matched '{r['vulnerability_profile']}' (+50)")

        # 2. File Path Match (+30)
        if norm_path and (norm_path == rec_path or norm_path.endswith(rec_path) or rec_path.endswith(norm_path)):
            score += 30
            rationales.append(f"Target file path matched '{r['file_path']}' (+30)")

        # 3. Test Failure Match (+25 per matching failure)
        for ft in failed_set:
            if ft in rec_pattern or any(ft in str(s).lower() for s in scenarios):
                score += 25
                rationales.append(f"Failed test '{ft}' matched historical pattern (+25)")
                break

        if score > 0:
            rec = MemoryRecord(
                id=r["id"],
                vulnerability_profile=r["vulnerability_profile"],
                file_path=r["file_path"],
                failure_pattern=r["failure_pattern"],
                sanitized_explanation=r["sanitized_explanation"],
                remediation_pattern=r["remediation_pattern"],
                trusted_test_scenarios=scenarios,
                historical_limitations=r["historical_limitations"],
                created_at=r["created_at"],
                relevance_score=score,
                explainability="; ".join(rationales),
            )
            scored.append(rec)

    # Sort descending by relevance score, then created_at
    scored.sort(key=lambda m: (m.relevance_score, m.created_at), reverse=True)
    selected = scored[:limit]

    # Return as bounded advisory dictionaries
    return [s.to_advisory_dict() for s in selected]


def seed_default_memory(db: Any) -> None:
    """Pre-populates baseline regression patterns for BOLA and access control vulnerabilities."""
    patterns = [
        (
            "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            "app/access.py",
            "test_non_owner_access: authenticated non-owner user reads document",
            "Direct return of requested document without comparing document owner_id to session user",
            "Enforce strict ownership check: return document if owner == user else None",
            ["BOLA-OWNER-001", "BOLA-ATTACK-001", "BOLA-ATTACK-002", "BOLA-BOUNDARY-001"],
            "Applies to direct object references; hierarchical or role delegation policies require dedicated role models",
        ),
        (
            "BOLA-001",
            "app/access.py",
            "test_owner_access failed after patch: over-restrictive check blocks legitimate owner",
            "Patch reversed authorization equality condition or unconditionally returned None",
            "Verify equality check: owner == user must permit owner and reject non-owner",
            ["BOLA-OWNER-001", "BOLA-OWNER-002"],
            "Must preserve valid document dictionary return for authentic owner",
        ),
        (
            "MANIPULATED_IDENTIFIERS",
            "app/access.py",
            "test_manipulated_document_id: non-existent or malformed document id triggers unhandled 500",
            "Missing existence and document dictionary type check before inspecting owner",
            "Validate document existence before checking ownership: if not document: return None",
            ["BOLA-BOUNDARY-001", "BOLA-BOUNDARY-002"],
            "Document store contract requires dictionary or None return",
        ),
    ]

    for prof, path, pat, exp, rem, scens, lim in patterns:
        existing = db.execute(
            "SELECT id FROM regression_memory WHERE vulnerability_profile = ? AND failure_pattern = ?",
            (prof, pat),
        ).fetchone()
        if not existing:
            record_failure_pattern(
                db=db,
                vulnerability_profile=prof,
                file_path=path,
                failure_pattern=pat,
                sanitized_explanation=exp,
                remediation_pattern=rem,
                trusted_scenarios=scens,
                historical_limitations=lim,
            )
