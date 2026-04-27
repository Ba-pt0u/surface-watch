"""
base.py — Abstract base collector.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from surface_watch.models import CollectorResult

log = logging.getLogger(__name__)


class BaseCollector(ABC):
    """All collectors inherit from this and implement collect()."""

    name: str = "base"

    @abstractmethod
    def collect(self) -> CollectorResult:
        """Run a collection cycle and return discovered assets + edges."""
        ...

    def run(self) -> CollectorResult:
        """Wrapper that logs timing and catches errors."""
        log.info("[%s] Starting collection", self.name)
        start = time.monotonic()
        try:
            result = self.collect()
            result.duration_seconds = time.monotonic() - start
            log.info(
                "[%s] Completed in %.1fs — %d assets, %d edges, %d errors",
                self.name, result.duration_seconds,
                len(result.assets), len(result.edges), len(result.errors),
            )
            return result
        except Exception as exc:
            elapsed = time.monotonic() - start
            log.exception("[%s] Failed after %.1fs", self.name, elapsed)
            return CollectorResult(
                collector_name=self.name,
                errors=[str(exc)],
                duration_seconds=elapsed,
            )
