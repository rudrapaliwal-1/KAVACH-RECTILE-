"""Owned, sanitized local lifecycle records for generalized analysis.

The hosted Neatlogs export retains its separate nine-event allowlist.
"""
from __future__ import annotations

from uuid import uuid4
from fastapi import APIRouter, Request
from .auth import current_user
from .database import utc_now

EVENT_TYPES = frozenset({'SCAN_COMPLETED', 'AI_REVIEW_COMPLETED', 'PATCH_PROPOSED',
                         'PATCH_APPROVED', 'PATCH_REJECTED', 'PATCH_CHECKED',
                         'VIBECI_PREFLIGHT_COMPLETED', 'VIBECI_VERIFICATION_COMPLETED',
                         'VIBECI_RULES_CONFIGURED'})
router = APIRouter(tags=['activity'])


def record(db, project_id: str, event_type: str, reference_id: str, status: str) -> None:
    if event_type not in EVENT_TYPES or len(reference_id) > 80 or len(status) > 30:
        raise ValueError('invalid local lifecycle event')
    db.execute('INSERT INTO security_activity VALUES (?, ?, ?, ?, ?, ?, ?)',
               ('act-' + uuid4().hex, project_id, current_user(), event_type,
                reference_id, status, utc_now()))


@router.get('/api/security-activity')
def list_activity(request: Request):
    with request.app.state.workflow.db.read() as db:
        rows = db.execute('''SELECT a.id, a.project_id, p.name AS project_name, a.event_type,
                             a.reference_id, a.status, a.created_at
                             FROM security_activity a JOIN projects p ON p.id=a.project_id
                             WHERE p.owner_id=? ORDER BY a.created_at DESC LIMIT 500''', (current_user(),)).fetchall()
    return [dict(row) for row in rows]
