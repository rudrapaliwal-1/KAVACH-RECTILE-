"""Server-owned target authorization and immutable source snapshot identifiers."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from .policy import ALLOWED_PATHS, AUTHORIZED_TARGET


@dataclass(frozen=True)
class TargetManifest:
    target_app_id: str = AUTHORIZED_TARGET
    allowed_patch_paths: frozenset[str] = ALLOWED_PATHS
    protected_paths: frozenset[str] = frozenset({"tests", "test", "runner", "config"})
    verification_profile: str = "bola-required-tests-v1"
    patch_format: str = "unified_diff"
    max_snapshot_files: int = 2048
    max_snapshot_bytes: int = 32 * 1024 * 1024

    def source_revision(self, source_root: Path,
                        protected_tests_root: Path | None = None) -> str:
        """Hash the bounded target tree and, when configured, the actual protected suite."""
        from .safe_cache import safe_cache

        def _compute() -> str:
            roots = [(source_root.resolve(strict=True), "")]
            if protected_tests_root is not None:
                roots.append((protected_tests_root.resolve(strict=True), "protected_tests/"))
            digest = hashlib.sha256()
            count = total = read_total = directory_count = 0
            for root, prefix in roots:
                if not root.is_dir():
                    raise ValueError("authorized source root is not a directory")
                for directory, names, files in os.walk(root, followlinks=False):
                    directory_count += 1
                    if directory_count > self.max_snapshot_files:
                        raise ValueError("authorized source directory limit exceeded")
                    names.sort()
                    files.sort()
                    for name in names:
                        if (Path(directory) / name).is_symlink():
                            raise ValueError("authorized source contains a symlink")
                    for name in files:
                        path = Path(directory) / name
                        if path.is_symlink():
                            raise ValueError("authorized source contains a symlink")
                        relative = prefix + path.relative_to(root).as_posix()
                        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                        try:
                            details = os.fstat(fd)
                            if not stat.S_ISREG(details.st_mode):
                                raise ValueError("authorized source contains a special file")
                            count += 1
                            total += details.st_size
                            if count > self.max_snapshot_files or total > self.max_snapshot_bytes:
                                raise ValueError("authorized source snapshot limit exceeded")
                            digest.update(relative.encode("utf-8") + b"\0")
                            with os.fdopen(fd, "rb", closefd=False) as source:
                                while chunk := source.read(65536):
                                    read_total += len(chunk)
                                    if read_total > self.max_snapshot_bytes:
                                        raise ValueError("authorized source grew during snapshot")
                                    digest.update(chunk)
                        finally:
                            os.close(fd)
            for required in self.allowed_patch_paths:
                if not (roots[0][0] / required).is_file():
                    raise ValueError("authorized patch target is missing")
            return "sha256:" + digest.hexdigest()

        return safe_cache.get_or_compute_source_revision(source_root, protected_tests_root, _compute)


TARGET_MANIFEST = TargetManifest()
