"""Standard exit codes for CI/CD integration.

The pipeline decides pass/fail purely from the process exit code, so these
values are part of the tool's public contract and must be unambiguous.

When several conditions hold at once, the *most actionable / most severe*
engineering problem wins. The documented priority is:

    30 (BUILD_OR_CONFIG_ERROR)  -- nothing could be trusted; fix this first
    10 (VULN_REMAINS/NEW_ISSUE) -- a real security problem was confirmed
    20 (FUNC_REGRESSION)        -- the patch broke valid behaviour
    40 (INCONCLUSIVE)           -- not enough evidence to judge
     0 (PASS)                   -- everything required succeeded

A build error outranks everything because every other verdict is derived
from executing a build we could not actually produce.
"""

from __future__ import annotations

PASS = 0
VULN_OR_SECURITY = 10          # VULN_REMAINS or NEW_ISSUE
FUNC_REGRESSION = 20
BUILD_OR_CONFIG_ERROR = 30
INCONCLUSIVE = 40

# Higher number in this list == resolved earlier (wins).
_PRIORITY = [30, 10, 20, 40, 0]

NAMES = {
    0: "PASS",
    10: "VULN_OR_SECURITY",
    20: "FUNC_REGRESSION",
    30: "BUILD_OR_CONFIG_ERROR",
    40: "INCONCLUSIVE",
}


def resolve(codes) -> int:
    """Collapse a set of candidate exit codes into one per documented priority.

    >>> resolve([0])
    0
    >>> resolve([0, 20, 10])
    10
    >>> resolve([10, 20, 30])
    30
    >>> resolve([])
    0
    """
    present = set(codes)
    if not present:
        return PASS
    for code in _PRIORITY:
        if code in present:
            return code
    # Any unknown code is treated as a tool/config failure.
    return BUILD_OR_CONFIG_ERROR
