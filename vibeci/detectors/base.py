"""Base class for language/ecosystem project check detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from vibeci.models import CheckDefinition


class BaseDetector(ABC):
    """Abstract base detector for discovering project checks."""

    name: str = "base"

    @abstractmethod
    def is_applicable(self, root_dir: Path) -> bool:
        """Return True if this detector applies to the project in root_dir."""
        pass

    @abstractmethod
    def detect(self, root_dir: Path) -> list[CheckDefinition]:
        """Inspect the directory and return discovered CheckDefinitions."""
        pass
