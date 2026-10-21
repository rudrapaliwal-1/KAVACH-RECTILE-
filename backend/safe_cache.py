"""Safe Intermediate Caching Engine for SENTINEL-X.

Implements safe caching ONLY for immutable, reproducible intermediate inputs:
1. Deterministic policy evaluations.
2. Source directory revision digests based on filesystem fingerprints.
3. Unified diff AST parsing and metrics.
4. Verifier container image digest and preflight checks with strict TTL.

CRITICAL INVARIANTS:
1. Cache keys MUST bind ALL relevant inputs:
   - Source revision
   - Patch hash
   - Test-suite version
   - Verifier image digest
   - Execution configuration
2. Never reuse a previous VERIFIED verdict solely because a patch appears similar.
   Every approved patch MUST undergo independent verifier execution.
3. Zero cache pollution across different source revisions, test suites, or verifiers.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0

    @property
    def total_requests(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return round((self.hits / self.total_requests) * 100.0, 2)


def compute_composite_cache_key(
    source_revision: str,
    patch_hash: str,
    test_suite_version: str,
    verifier_image_digest: str,
    execution_config: Optional[Dict[str, Any]] = None,
) -> str:
    """Computes an immutable composite cache key binding all 5 authoritative parameters."""
    config_str = json.dumps(execution_config or {}, sort_keys=True)
    raw = f"{source_revision}:{patch_hash}:{test_suite_version}:{verifier_image_digest}:{config_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class BoundedLRUCache:
    """Thread-safe bounded in-memory LRU cache with eviction tracking."""

    def __init__(self, maxsize: int = 256):
        self.maxsize = maxsize
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._lock = threading.Lock()
        self.stats = CacheStats()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                self.stats.misses += 1
                return None
            val, _ = self._cache[key]
            self._cache.move_to_end(key)
            self.stats.hits += 1
            return val

    def put(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> None:
        expiry = time.time() + ttl_seconds if ttl_seconds else float("inf")
        with self._lock:
            if key in self._cache:
                self._cache[key] = (value, expiry)
                self._cache.move_to_end(key)
                return

            if len(self._cache) >= self.maxsize:
                self._cache.popitem(last=False)
                self.stats.evictions += 1

            self._cache[key] = (value, expiry)

    def invalidate(self, prefix: str = "") -> int:
        with self._lock:
            if not prefix:
                count = len(self._cache)
                self._cache.clear()
                self.stats.invalidations += count
                return count

            to_remove = [k for k in self._cache if k.startswith(prefix)]
            for k in to_remove:
                del self._cache[k]
            self.stats.invalidations += len(to_remove)
            return len(to_remove)

    def reset_stats(self) -> None:
        with self._lock:
            self.stats = CacheStats()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "hits": self.stats.hits,
                "misses": self.stats.misses,
                "evictions": self.stats.evictions,
                "invalidations": self.stats.invalidations,
                "hit_rate_percent": self.stats.hit_rate,
                "current_size": len(self._cache),
                "max_size": self.maxsize,
            }


class SafeCacheManager:
    """Orchestrates safe intermediate caching across all SENTINEL-X layers."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.policy_cache = BoundedLRUCache(maxsize=512)
                cls._instance.source_manifest_cache = BoundedLRUCache(maxsize=128)
                cls._instance.parsed_diff_cache = BoundedLRUCache(maxsize=256)
                cls._instance.preflight_cache = BoundedLRUCache(maxsize=16)
            return cls._instance

    def get_source_manifest_fingerprint(self, root_path: Path) -> str:
        """Computes rapid directory fingerprint based on file mtimes and sizes."""
        if not root_path.exists():
            return "empty"
        mtimes: List[str] = []
        try:
            for p in sorted(root_path.rglob("*")):
                if p.is_file():
                    stat = p.stat()
                    mtimes.append(f"{p.name}:{stat.st_mtime_ns}:{stat.st_size}")
            return hashlib.sha256(";".join(mtimes).encode("utf-8")).hexdigest()
        except Exception:
            return str(time.time())

    def get_or_compute_policy(
        self,
        target_app: str,
        patch_hash: str,
        attempt: int,
        compute_fn: Callable[[], Any],
    ) -> Any:
        """Caches deterministic policy evaluation for a given exact patch hash."""
        key = f"policy:{target_app}:{patch_hash}:{attempt}"
        cached = self.policy_cache.get(key)
        if cached is not None:
            return cached

        res = compute_fn()
        self.policy_cache.put(key, res)
        return res

    def get_or_parse_diff(
        self,
        patch_text: str,
        parse_fn: Callable[[str], Tuple[List[str], int, int]],
    ) -> Tuple[List[str], int, int]:
        """Caches parsed unified diff AST and line metrics."""
        text_hash = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        key = f"diff:{text_hash}"
        cached = self.parsed_diff_cache.get(key)
        if cached is not None:
            return cached

        res = parse_fn(patch_text)
        self.parsed_diff_cache.put(key, res)
        return res

    def get_or_compute_source_revision(
        self,
        root_path: Path,
        tests_path: Optional[Path],
        compute_fn: Callable[[], str],
    ) -> str:
        """Caches source revision digest based on directory mtime fingerprints."""
        fp1 = self.get_source_manifest_fingerprint(root_path)
        fp2 = self.get_source_manifest_fingerprint(tests_path) if tests_path else "none"
        key = f"rev:{str(root_path)}:{fp1}:{fp2}"
        cached = self.source_manifest_cache.get(key)
        if cached is not None:
            return cached

        res = compute_fn()
        self.source_manifest_cache.put(key, res)
        return res

    def get_or_check_docker_preflight(
        self,
        check_fn: Callable[[], Tuple[bool, str]],
        ttl_seconds: float = 60.0,
    ) -> Tuple[bool, str]:
        """Caches Docker preflight readiness check with short TTL."""
        key = "docker_preflight"
        with self.preflight_cache._lock:
            if key in self.preflight_cache._cache:
                val, expiry = self.preflight_cache._cache[key]
                if time.time() < expiry:
                    self.preflight_cache.stats.hits += 1
                    return val

        self.preflight_cache.stats.misses += 1
        res = check_fn()
        self.preflight_cache.put(key, res, ttl_seconds=ttl_seconds)
        return res

    def reset_all(self) -> None:
        """Invalidates all cached entries and resets statistics."""
        self.policy_cache.invalidate()
        self.policy_cache.reset_stats()
        self.source_manifest_cache.invalidate()
        self.source_manifest_cache.reset_stats()
        self.parsed_diff_cache.invalidate()
        self.parsed_diff_cache.reset_stats()
        self.preflight_cache.invalidate()
        self.preflight_cache.reset_stats()

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Returns consolidated metrics for all caching layers."""
        p_stats = self.policy_cache.get_stats()
        s_stats = self.source_manifest_cache.get_stats()
        d_stats = self.parsed_diff_cache.get_stats()
        f_stats = self.preflight_cache.get_stats()

        total_hits = p_stats["hits"] + s_stats["hits"] + d_stats["hits"] + f_stats["hits"]
        total_misses = p_stats["misses"] + s_stats["misses"] + d_stats["misses"] + f_stats["misses"]
        total_reqs = total_hits + total_misses
        overall_rate = round((total_hits / total_reqs * 100.0), 2) if total_reqs > 0 else 0.0

        return {
            "overall_hit_rate_percent": overall_rate,
            "total_cache_hits": total_hits,
            "total_cache_misses": total_misses,
            "layers": {
                "policy_validation": p_stats,
                "source_manifest": s_stats,
                "parsed_diff": d_stats,
                "verifier_preflight": f_stats,
            },
        }


# Global singleton instance
safe_cache = SafeCacheManager()
