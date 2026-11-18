"""Unified-diff parsing and diff generation between two source trees.

We produce, per changed file, the set of line numbers that were *added or
modified in the new (patched) version*, plus the hunk headers (which often
name the enclosing function). This is what the correlation stage maps crash
frames onto.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    # line numbers (in the NEW file) that were added/changed
    added_lines: set[int] = field(default_factory=set)
    # (start,end) ranges in the NEW file touched by a hunk (context included)
    hunk_ranges: list[tuple[int, int]] = field(default_factory=list)
    # function names appearing in '@@ ... @@ <context>' headers
    hunk_functions: list[str] = field(default_factory=list)

    @property
    def basename(self) -> str:
        return os.path.basename(self.new_path)


@dataclass
class Diff:
    files: list[FileDiff] = field(default_factory=list)
    raw: str = ""

    def by_basename(self, name: str) -> FileDiff | None:
        for f in self.files:
            if f.basename == name:
                return f
        return None

    def changed_basenames(self) -> set[str]:
        return {f.basename for f in self.files}

    def summary(self) -> dict:
        return {
            "files": [
                {
                    "new_path": f.new_path,
                    "added_line_count": len(f.added_lines),
                    "hunk_functions": f.hunk_functions,
                }
                for f in self.files
            ]
        }


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$")
_FUNC_HINT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# a +++ header: "+++ b/path/file.c" or "+++ patched/file.c"
_NEWFILE_RE = re.compile(r"^\+\+\+\s+(?:b/)?(.+?)\s*$")
_OLDFILE_RE = re.compile(r"^---\s+(?:a/)?(.+?)\s*$")


def parse(diff_text: str) -> Diff:
    """Parse a unified diff into structured per-file change data."""
    diff = Diff(raw=diff_text)
    cur: FileDiff | None = None
    new_lineno = 0
    old_name = ""
    for line in diff_text.splitlines():
        mo = _OLDFILE_RE.match(line)
        if mo and (cur is None or not line.startswith("---- ")):
            old_name = mo.group(1)
            continue
        mn = _NEWFILE_RE.match(line)
        if mn:
            new_name = mn.group(1)
            cur = FileDiff(old_path=old_name, new_path=new_name)
            diff.files.append(cur)
            continue
        if line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if m and cur is not None:
                start = int(m.group(1))
                length = int(m.group(2) or "1")
                new_lineno = start
                cur.hunk_ranges.append((start, start + max(0, length - 1)))
                ctx = m.group(3).strip()
                if ctx:
                    fm = _FUNC_HINT_RE.search(ctx)
                    if fm:
                        cur.hunk_functions.append(fm.group(1))
            continue
        if cur is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            cur.added_lines.add(new_lineno)
            new_lineno += 1
        elif line.startswith("-") and not line.startswith("---"):
            # deletion: does not advance the new-file counter
            pass
        else:
            # context line advances new-file counter
            new_lineno += 1
    return diff


def generate(base_dir: str, patched_dir: str) -> Diff:
    """Compute a unified diff between two source trees using git (no-index).

    git is used purely as a diff engine; neither tree needs to be a repo.
    Paths in the resulting diff are normalised to be relative to the trees so
    that basenames line up with crash-frame file names.
    """
    try:
        proc = subprocess.run(
            ["git", "--no-pager", "diff", "--no-index", "--no-color",
             "-U3", base_dir, patched_dir],
            capture_output=True, text=True, timeout=60,
        )
        text = proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        text = ""
    # git --no-index prefixes paths with the given dir; strip to basename-friendly form
    return parse(text)
