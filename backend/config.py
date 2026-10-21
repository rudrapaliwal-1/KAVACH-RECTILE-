"""Environment configuration. Missing credentials leave the API closed."""

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


_CALLABLE = re.compile(r"^(agent|verification)(?:\.[A-Za-z][A-Za-z0-9_]*)+:[A-Za-z][A-Za-z0-9_]*$")
_OPERATOR = re.compile(r"^[A-Za-z0-9_.@-]{1,80}$")


@dataclass(frozen=True)
class Settings:
    database_path: Path
    source_root: Path
    project_root: Path = Path("backend/project_data")
    protected_tests_root: Path | None = None
    environment: str = "demo"
    frontend_origin: str = "http://localhost:5173"
    operator_name: str = "local-operator"
    operator_token: str = field(default="", repr=False)
    agent_callable: str = ""
    verifier_callable: str = ""
    max_request_bytes: int = 16_384
    max_patch_bytes: int = 32_768
    max_changed_files: int = 1
    max_source_bytes: int = 16_384
    max_revisions: int = 2
    planner_timeout_seconds: float = 300.0
    verifier_timeout_seconds: float = 300.0
    lease_seconds: float = 30.0
    github_webhook_secret: str = field(default="", repr=False)
    github_token: str = field(default="", repr=False)
    github_allowed_repositories: str = ""
    sentinel_base_url: str = "http://localhost:5173"

    def __post_init__(self) -> None:
        if self.environment not in ("development", "demo", "production"):
            raise ValueError("invalid SENTINEL_ENV")
        if self.environment == "production":
            raise ValueError("production identity provider and isolated verifier are not configured")
        if (self.verifier_callable == "verification.adapter:verify_backend_patch"
                and self.protected_tests_root is None):
            raise ValueError("SENTINEL_PROTECTED_TESTS_ROOT is required for integrated verification")
        if self.operator_token and (len(self.operator_token) < 32 or
                                    not self.operator_token.isascii() or
                                    len(self.operator_token) > 256):
            raise ValueError("SENTINEL_OPERATOR_TOKEN must be 32-256 ASCII characters")
        if not _OPERATOR.fullmatch(self.operator_name):
            raise ValueError("invalid operator name")
        origin = urlsplit(self.frontend_origin)
        if (origin.scheme not in ("http", "https") or not origin.netloc or
                origin.path or origin.query or origin.fragment or
                origin.username or origin.password or "*" in self.frontend_origin):
            raise ValueError("SENTINEL_FRONTEND_ORIGIN must be one exact HTTP(S) origin")
        if (origin.scheme == "http" and origin.hostname not in
                ("localhost", "127.0.0.1", "[::1]", "::1")):
            raise ValueError("non-local frontend origins require HTTPS")
        for name, spec, prefix in (("SENTINEL_AGENT_CALLABLE", self.agent_callable, "agent."),
                                   ("SENTINEL_VERIFIER_CALLABLE", self.verifier_callable, "verification.")):
            if spec and (not _CALLABLE.fullmatch(spec) or not spec.startswith(prefix)):
                raise ValueError(f"{name} must name a public callable in {prefix}*")
        if self.max_request_bytes <= 0 or self.max_patch_bytes <= 0 or self.max_source_bytes <= 0:
            raise ValueError("size limits must be positive")
        if self.max_changed_files != 1 or self.max_revisions != 2:
            raise ValueError("MVP policy requires one changed file and two revisions")
        if any(not math.isfinite(value) or value <= 0 for value in
               (self.planner_timeout_seconds, self.verifier_timeout_seconds, self.lease_seconds)):
            raise ValueError("integration timeouts must be positive and finite")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_path=Path(os.getenv("SENTINEL_DB_PATH", "backend/sentinel.db")),
            environment=os.getenv("SENTINEL_ENV", "demo"),
            source_root=Path(os.getenv("SENTINEL_SOURCE_ROOT", ".")),
            project_root=Path(os.getenv("SENTINEL_PROJECT_ROOT", "backend/project_data")),
            protected_tests_root=(Path(os.environ["SENTINEL_PROTECTED_TESTS_ROOT"])
                                  if os.getenv("SENTINEL_PROTECTED_TESTS_ROOT") else None),
            frontend_origin=os.getenv("SENTINEL_FRONTEND_ORIGIN", "http://localhost:5173"),
            operator_name=os.getenv("SENTINEL_OPERATOR_NAME", "local-operator"),
            operator_token=os.getenv("SENTINEL_OPERATOR_TOKEN", ""),
            agent_callable=os.getenv("SENTINEL_AGENT_CALLABLE", ""),
            verifier_callable=os.getenv("SENTINEL_VERIFIER_CALLABLE", ""),
            max_request_bytes=int(os.getenv("SENTINEL_MAX_REQUEST_BYTES", "16384")),
            planner_timeout_seconds=float(os.getenv("SENTINEL_PLANNER_TIMEOUT_SECONDS", "300")),
            verifier_timeout_seconds=float(os.getenv("SENTINEL_VERIFIER_TIMEOUT_SECONDS", "300")),
            lease_seconds=float(os.getenv("SENTINEL_LEASE_SECONDS", "30")),
            github_webhook_secret=os.getenv("SENTINEL_GITHUB_WEBHOOK_SECRET", ""),
            github_token=os.getenv("SENTINEL_GITHUB_TOKEN", ""),
            github_allowed_repositories=os.getenv("SENTINEL_GITHUB_ALLOWED_REPOSITORIES", ""),
            sentinel_base_url=os.getenv("SENTINEL_BASE_URL", os.getenv("SENTINEL_FRONTEND_ORIGIN", "http://localhost:5173")),
        )
