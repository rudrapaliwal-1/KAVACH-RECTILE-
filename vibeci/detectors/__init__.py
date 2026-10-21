"""Detectors registry for VibeCI."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from vibeci.detectors.base import BaseDetector
from vibeci.detectors.javascript import JavaScriptDetector
from vibeci.detectors.python import PythonDetector
from vibeci.models import CheckDefinition

ALL_DETECTORS: list[BaseDetector] = [
    PythonDetector(),
    JavaScriptDetector(),
]


def discover_checks(root_dir: Path) -> tuple[str, list[CheckDefinition]]:
    """Discover all applicable checks in the target root_dir.

    Returns:
        (detected_ecosystems, list_of_checks)
    """
    root_dir = root_dir.resolve()
    applicable_detectors: list[BaseDetector] = []
    checks: list[CheckDefinition] = []

    active_ecosystems: list[str] = []
    for detector in ALL_DETECTORS:
        if detector.is_applicable(root_dir):
            applicable_detectors.append(detector)
            detected = detector.detect(root_dir)
            if detected:
                active_ecosystems.append(detector.name)
            checks.extend(detected)

    chosen = active_ecosystems if active_ecosystems else [d.name for d in applicable_detectors]
    ecosystems = ", ".join(chosen) if chosen else "none"
    return ecosystems, checks
