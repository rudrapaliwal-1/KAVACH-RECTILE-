"""API authentication, CSRF protection, and bounded request bodies."""
from contextvars import ContextVar
from uuid import uuid4

from fastapi.responses import JSONResponse

from .approvals import require_operator
from .auth import COOKIE, csrf_valid, identity_kind, principal, session_user
from .models import WorkflowError

correlation_id: ContextVar[str | None] = ContextVar("sentinel_correlation_id", default=None)
PUBLIC = frozenset({
    "/api/auth/register",
    "/api/auth/login",
    "/api/attestation/verify",
    "/api/jobs/attestation/verify",
    "/api/webhooks/github",
})
SAFE = frozenset({"GET", "HEAD", "OPTIONS"})


class ApiGuard:
    def __init__(self, app, settings, db):
        self.app, self.settings, self.db = app, settings, db

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] != "http" or not path.startswith("/api/") or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        request_id = "req-" + uuid4().hex
        context = correlation_id.set(request_id)
        user_context = principal.set(None)
        kind_context = identity_kind.set(None)
        headers = scope.get("headers", [])
        method = scope.get("method", "GET")

        async def reply(status, message, code):
            await JSONResponse(status_code=status, content={"detail": message, "code": code},
                               headers={"Cache-Control": "no-store", "X-Correlation-ID": request_id})(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": list(message.get("headers", [])) + [
                    (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"), (b"x-correlation-id", request_id.encode())]}
            await send(message)

        try:
            if path not in PUBLIC:
                cookies = [v.decode("latin-1") for k, v in headers if k.lower() == b"cookie"]
                raw_token = ""
                for cookie_line in cookies:
                    for pair in cookie_line.split(";"):
                        name, sep, value = pair.strip().partition("=")
                        if sep and name == COOKIE:
                            raw_token = value
                with self.db.read() as db:
                    user_id = session_user(db, raw_token)
                if user_id:
                    principal.set(user_id)
                    identity_kind.set("USER_SESSION")
                    if method not in SAFE:
                        csrf_headers = [v.decode("latin-1") for k, v in headers if k.lower() == b"x-csrf-token"]
                        with self.db.read() as db:
                            valid = len(csrf_headers) == 1 and csrf_valid(db, raw_token, csrf_headers[0])
                        if not valid:
                            await reply(403, "CSRF token is missing or invalid", "CSRF_FAILED")
                            return
                else:
                    tokens = [v.decode("latin-1") for k, v in headers if k.lower() == b"x-operator-token"]
                    if len(tokens) != 1:
                        await reply(401, "login required", "AUTH_REQUIRED")
                        return
                    try:
                        operator = require_operator(self.settings, tokens[0])
                    except WorkflowError as error:
                        await reply(error.http_status, str(error), "AUTH_REQUIRED")
                        return
                    principal.set(operator)
                    identity_kind.set("DEMO_SHARED_TOKEN")

            if method in SAFE:
                await self.app(scope, receive, secure_send)
                return
            limits = 64 * 1024 * 1024 if path.startswith("/api/projects/") and (path.endswith("/upload") or path.endswith("/upload-file")) else (1024 * 1024 if path == "/api/webhooks/github" else self.settings.max_request_bytes)
            lengths = [v for k, v in headers if k.lower() == b"content-length"]
            if len(lengths) > 1:
                await reply(400, "invalid content length", "INVALID_REQUEST")
                return
            if lengths:
                try:
                    size = int(lengths[0])
                except ValueError:
                    size = -1
                if size < 0 or size > limits:
                    await reply(413, "request body too large", "REQUEST_TOO_LARGE")
                    return
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    await reply(400, "invalid request stream", "INVALID_REQUEST")
                    return
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > limits:
                    await reply(413, "request body too large", "REQUEST_TOO_LARGE")
                    return
                body.extend(chunk)
                if not message.get("more_body", False):
                    break
            delivered = False
            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()
            await self.app(scope, replay, secure_send)
        finally:
            correlation_id.reset(context)
            principal.reset(user_context)
            identity_kind.reset(kind_context)
