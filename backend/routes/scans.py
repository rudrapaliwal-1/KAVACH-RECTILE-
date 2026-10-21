"""Owned, non-executing repository scans and structured finding reads."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from uuid import uuid4

from fastapi import APIRouter, Request, Query
from pydantic import BaseModel, Field

from ..ai_provider import GeminiReviewProvider, ProviderUnavailable

from ..analysis import scan
from ..auth import current_user
from ..database import utc_now
from ..models import WorkflowError
from ..security_activity import record
from .projects import _project, _source_dir

router = APIRouter(tags=['analysis'])


def _rows(request: Request, query: str, args: tuple = ()) -> list[dict]:
    with request.app.state.workflow.db.read() as db:
        return [dict(row) for row in db.execute(query, args).fetchall()]


@router.post('/api/projects/{project_id}/scan', status_code=201)
def start_scan(project_id: str, request: Request):
    project = _project(request, project_id)
    if project['status'] == 'CREATED':
        raise WorkflowError('upload a repository before scanning', 409, 'UPLOAD_REQUIRED')
    root = _source_dir(request, project_id)
    if not root.is_dir() or root.is_symlink():
        raise WorkflowError('project source is unavailable', 409, 'SOURCE_UNAVAILABLE')
    profile, findings = scan(root)
    scan_id = 'scan-' + uuid4().hex
    now = utc_now()
    with request.app.state.workflow.db.transaction() as db:
        db.execute('''INSERT INTO project_scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (scan_id, project_id, profile['status'], profile['framework'],
                    json.dumps(profile['languages']), json.dumps(profile['manifests']),
                    profile['file_count'], profile['reason'], now, now))
        record(db, project_id, 'SCAN_COMPLETED', scan_id, profile['status'])
        for finding in findings:
            db.execute('''INSERT INTO scan_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       ('sf-' + uuid4().hex, scan_id, project_id, finding['category'],
                        finding['severity'], finding['confidence'], finding['file_path'],
                        finding['line_start'], finding['line_end'], finding['evidence'],
                        finding['explanation'], finding['recommendation'], finding['detection_source'],
                        finding['validation_status'], now))
    return {'id': scan_id, 'project_id': project_id, **profile, 'finding_count': len(findings),
            'created_at': now, 'completed_at': now}


@router.get('/api/projects/{project_id}/scans')
def project_scans(project_id: str, request: Request):
    _project(request, project_id)
    rows = _rows(request, '''SELECT s.*,
                             (SELECT count(*) FROM scan_findings f WHERE f.scan_id = s.id) AS finding_count
                             FROM project_scans s WHERE s.project_id = ? ORDER BY s.created_at DESC''', (project_id,))
    for row in rows:
        row['languages'] = json.loads(row.pop('languages_json'))
        row['manifests'] = json.loads(row.pop('manifest_json'))
    return rows


@router.get('/api/projects/{project_id}/findings')
def project_findings(project_id: str, request: Request):
    _project(request, project_id)
    return _rows(request, 'SELECT * FROM scan_findings WHERE project_id = ? ORDER BY created_at DESC, file_path, line_start', (project_id,))


@router.get('/api/scans')
def all_scans(request: Request):
    rows = _rows(request, '''SELECT s.*, p.name AS project_name,
                             (SELECT count(*) FROM scan_findings f WHERE f.scan_id=s.id) AS finding_count
                             FROM project_scans s JOIN projects p ON p.id=s.project_id
                             WHERE p.owner_id=? ORDER BY s.created_at DESC LIMIT 500''', (current_user(),))
    for row in rows:
        row['languages'] = json.loads(row.pop('languages_json'))
        row['manifests'] = json.loads(row.pop('manifest_json'))
    return rows


@router.get('/api/scan-findings')
def all_findings(request: Request):
    return _rows(request, '''SELECT f.*, p.name AS project_name FROM scan_findings f
                   JOIN projects p ON p.id = f.project_id WHERE p.owner_id = ?
                   ORDER BY f.created_at DESC LIMIT 500''', (current_user(),))


@router.get('/api/scan-findings/{finding_id}')
def finding_detail(finding_id: str, request: Request):
    rows = _rows(request, '''SELECT f.*, p.name AS project_name FROM scan_findings f
                   JOIN projects p ON p.id = f.project_id WHERE f.id = ? AND p.owner_id = ?''',
                 (finding_id, current_user()))
    if not rows:
        raise WorkflowError('finding not found', 404, 'FINDING_NOT_FOUND')
    return rows[0]


@router.get('/api/projects/{project_id}/ai-review/preview')
def ai_review_preview(project_id: str, request: Request, scan_id: str = Query(min_length=1)):
    _project(request, project_id)
    rows = _rows(request, '''SELECT DISTINCT file_path FROM scan_findings
                             WHERE project_id = ? AND scan_id = ? ORDER BY file_path LIMIT 20''', (project_id, scan_id))
    root = _source_dir(request, project_id).resolve()
    files = []
    from .projects import SENSITIVE
    for row in rows:
        if SENSITIVE.search(row['file_path']):
            continue
        relative = PurePosixPath(row['file_path'])
        if relative.is_absolute() or '..' in relative.parts:
            continue
        path = (root / row['file_path']).resolve()
        if path.is_relative_to(root) and path.is_file() and not path.is_symlink():
            files.append({'path': row['file_path'], 'bytes_to_send_max': min(path.stat().st_size, 4096)})
    return {'project_id': project_id, 'scan_id': scan_id, 'files': files,
            'requires_explicit_consent': True,
            'message': 'No source is sent to an external AI provider by upload or static scan.'}


class ReviewRequest(BaseModel):
    scan_id: str
    approved_files: list[str] = Field(min_length=1, max_length=20)
    consent: bool


@router.get('/api/ai/readiness')
def ai_readiness():
    import os
    return {'configured': bool(os.environ.get('GEMINI_API_KEY', '').strip()),
            'source_sharing': 'explicit consent required', 'status': 'READY' if os.environ.get('GEMINI_API_KEY', '').strip() else 'NOT_CONFIGURED'}


@router.post('/api/projects/{project_id}/ai-review')
def ai_review(project_id: str, payload: ReviewRequest, request: Request):
    _project(request, project_id)
    if payload.consent is not True:
        raise WorkflowError('explicit source sharing consent is required', 422, 'CONSENT_REQUIRED')
    rows = _rows(request, 'SELECT id FROM project_scans WHERE id=? AND project_id=?', (payload.scan_id, project_id))
    if not rows:
        raise WorkflowError('scan not found', 404, 'SCAN_NOT_FOUND')
    findings = _rows(request, 'SELECT id, category, severity, confidence, file_path, line_start, evidence FROM scan_findings WHERE scan_id=? AND project_id=? ORDER BY file_path, line_start LIMIT 100',
                     (payload.scan_id, project_id))
    allowed = set(sorted({row['file_path'] for row in findings})[:20])
    selected = set(payload.approved_files)
    if len(selected) != len(payload.approved_files) or not selected <= allowed:
        raise WorkflowError('approved files must exactly match previewed finding files', 422, 'INVALID_FILE_SELECTION')
    root = _source_dir(request, project_id).resolve()
    from .projects import SENSITIVE
    if any(SENSITIVE.search(name) for name in selected):
        raise WorkflowError('sensitive paths cannot be sent for AI review', 422, 'SENSITIVE_SOURCE')
    snippets = []
    for name in sorted(selected):
        relative = PurePosixPath(name)
        path = (root / name).resolve()
        if relative.is_absolute() or '..' in relative.parts or not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            raise WorkflowError('source file unavailable', 409, 'SOURCE_UNAVAILABLE')
        if path.stat().st_size > 128 * 1024:
            raise WorkflowError('source file exceeds AI review limit', 422, 'FILE_TOO_LARGE')
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        relevant = [row for row in findings if row['file_path'] == name]
        intervals = set()
        for row in relevant:
            intervals.update(range(max(0, row['line_start'] - 4), min(len(lines), row['line_start'] + 3)))
        snippet = '\n'.join(f'{n + 1}: {lines[n]}' for n in sorted(intervals))[:4096]
        from ..analysis import SECRET_NAME
        snippet = '\n'.join('[REDACTED SENSITIVE LINE]' if SECRET_NAME.search(line) else line for line in snippet.splitlines())
        snippets.append({'path': name, 'context': snippet})
    try:
        provider = GeminiReviewProvider()
    except ProviderUnavailable as exc:
        raise WorkflowError(str(exc), 503, 'AI_UNAVAILABLE') from None
    consent_id = 'consent-' + uuid4().hex
    with request.app.state.workflow.db.transaction() as db:
        db.execute('INSERT INTO source_share_consents (id, project_id, scan_id, user_id, files_json, model, created_at, purpose) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                   (consent_id, project_id, payload.scan_id, current_user(), json.dumps(sorted(selected)), provider.model, utc_now(), 'AI_REVIEW'))
    try:
        result, model = provider.review({'findings': [row for row in findings if row['file_path'] in selected], 'source_context': snippets})
    except ProviderUnavailable as exc:
        raise WorkflowError(str(exc), 503, 'AI_UNAVAILABLE') from None
    allowed_ids = {row['id'] for row in findings if row['file_path'] in selected}
    items = [item.model_dump() for item in result.items if item.finding_id in allowed_ids]
    for item in items:
        item['assessment'] = 'POTENTIAL' if item['assessment'] == 'POTENTIAL' else 'INCONCLUSIVE'
    review_id = 'review-' + uuid4().hex
    with request.app.state.workflow.db.transaction() as db:
        db.execute('INSERT INTO scan_ai_reviews VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (review_id, payload.scan_id, project_id, consent_id, model, json.dumps(items), utc_now()))
        record(db, project_id, 'AI_REVIEW_COMPLETED', review_id, 'POTENTIAL')
    return {'id': review_id, 'consent_id': consent_id, 'scan_id': payload.scan_id, 'items': items,
            'notice': 'AI review is advisory and does not establish exploitability or verification.'}


@router.get('/api/scan-findings/{finding_id}/reviews')
def finding_reviews(finding_id: str, request: Request):
    finding = _rows(request, '''SELECT f.id, f.scan_id FROM scan_findings f JOIN projects p ON p.id=f.project_id
                                WHERE f.id=? AND p.owner_id=?''', (finding_id, current_user()))
    if not finding:
        raise WorkflowError('finding not found', 404, 'FINDING_NOT_FOUND')
    rows = _rows(request, 'SELECT id, response_json, created_at FROM scan_ai_reviews WHERE scan_id=? ORDER BY created_at DESC LIMIT 20', (finding[0]['scan_id'],))
    return [{'id': row['id'], 'created_at': row['created_at'],
             'items': [item for item in json.loads(row['response_json']) if item.get('finding_id') == finding_id]}
            for row in rows if any(item.get('finding_id') == finding_id for item in json.loads(row['response_json']))]
