"""Shared in-memory data model linking runs, crashes and verdicts.

Kept dependency-free (only dataclasses) so every other module can import it
without creating import cycles.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .runner import RunResult
from .crash import CrashInfo
from .config import TestCase


@dataclass
class Execution:
    """One execution of one test against one (version, mode) binary."""
    version: str            # "base" | "patched"
    mode: str               # "release" | "sanitized"
    run: RunResult
    crash: CrashInfo


@dataclass
class TestRecord:
    """All executions of a single test, keyed by (version, mode)."""
    __test__ = False  # not a pytest test class
    test: TestCase
    executions: dict[tuple[str, str], Execution] = field(default_factory=dict)

    def get(self, version: str, mode: str) -> Execution | None:
        return self.executions.get((version, mode))


# Finding status vocabulary (security axis)
FIXED = "FIXED"
VULN_REMAINS = "VULN_REMAINS"
INCOMPLETE_FIX = "INCOMPLETE_FIX"
NEW_ISSUE = "NEW_ISSUE"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_TRIGGERED = "NOT_TRIGGERED"   # security probe that crashes neither version
STALE = "STALE"                   # regression test recorded against another base
# Finding status (functional axis)
FUNC_REGRESSION = "FUNC_REGRESSION"
FUNC_OK = "FUNC_OK"
FUNC_BASELINE_BROKEN = "FUNC_BASELINE_BROKEN"


# Correlation confidence
CORR_STRONG = "strong"
CORR_WEAK = "weak"
CORR_UNCLEAR = "unclear"      # evidence insufficient -> must be reported as such
CORR_NONE = "none"


@dataclass
class Correlation:
    confidence: str
    matched_files: list[str] = field(default_factory=list)
    matched_functions: list[str] = field(default_factory=list)
    matched_lines: list[str] = field(default_factory=list)
    explanation: str = ""
    relation: str | None = None          # crash_site_line | crash_site_function | caller_function | file_only
    side: str | None = None              # base | patched

    def summary(self) -> dict:
        return {
            "confidence": self.confidence,
            "relation": self.relation,
            "side": self.side,
            "matched_files": self.matched_files,
            "matched_functions": self.matched_functions,
            "matched_lines": self.matched_lines,
            "explanation": self.explanation,
        }


@dataclass
class Finding:
    """A single security/functional conclusion with its supporting evidence."""
    test_id: str
    axis: str                       # "security" | "functional"
    status: str
    error_type: str | None = None
    detection: str | None = None
    base_evidence: dict | None = None
    patched_evidence: dict | None = None
    correlation: Correlation | None = None
    stability: dict | None = None    # replay stability info
    reproducer: dict | None = None   # reproducer bundle path etc.
    note: str = ""
    per_mode: dict = field(default_factory=dict)      # mode -> verdict details
    decisive_mode: str | None = None
    base_identity: tuple | None = None                # (type, relpath, function)

    def summary(self) -> dict:
        return {
            "test_id": self.test_id,
            "axis": self.axis,
            "status": self.status,
            "decisive_mode": self.decisive_mode,
            "per_mode": self.per_mode,
            "error_type": self.error_type,
            "detection": self.detection,
            "correlation": self.correlation.summary() if self.correlation else None,
            "stability": self.stability,
            "reproducer": self.reproducer,
            "base_evidence": self.base_evidence,
            "patched_evidence": self.patched_evidence,
            "note": self.note,
        }
