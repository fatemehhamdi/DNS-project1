"""Patch diff extraction with relative paths and changed-function mapping.

Two ways to obtain the change set:
  * generate(base_dir, patched_dir) -- compare the two source trees directly
    (no git required); every path is RELATIVE to its tree root.
  * parse(diff_text, base_dir, patched_dir, strip=1) -- read a unified/git
    diff (e.g. the patch file under review), strip the leading path
    components like `patch -p1`, and resolve against the trees.

For each changed file we keep
  old_changed  -- changed/deleted line numbers in the BASE file
  new_changed  -- changed/added line numbers in the PATCHED file
  old_functions / new_functions -- functions (C/C++ heuristic parser) whose
                  body contains a changed line on that side.
Keeping both coordinate systems lets a crash observed on the base version be
matched against base-side lines, and a crash on the patched version against
patched-side lines.
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field

_TEXT_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inc", ".ipp",
             ".mk", ".cmake", ".txt", ".in", ".sh", ".s", ".S"}
_TEXT_NAMES = {"Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "configure",
               "meson.build", "build.sh"}


@dataclass
class FileDiff:
    relpath: str
    status: str = "modified"                 # modified | added | removed
    old_changed: set[int] = field(default_factory=set)
    new_changed: set[int] = field(default_factory=set)
    old_functions: set[str] = field(default_factory=set)
    new_functions: set[str] = field(default_factory=set)
    # lines adjacent to a pure insertion/deletion: used ONLY to decide which
    # function was modified, never reported as a "changed line"
    old_anchor: set[int] = field(default_factory=set)
    new_anchor: set[int] = field(default_factory=set)

    @property
    def functions(self) -> set[str]:
        return self.old_functions | self.new_functions


@dataclass
class Diff:
    files: list[FileDiff] = field(default_factory=list)
    raw: str = ""
    source: str = "tree"                     # tree | file

    def get(self, relpath: str) -> FileDiff | None:
        rel = os.path.normpath(relpath)
        for f in self.files:
            if f.relpath == rel:
                return f
        return None

    def summary(self) -> dict:
        return {"source": self.source, "files": [
            {"path": f.relpath, "status": f.status,
             "base_changed_lines": len(f.old_changed),
             "patched_changed_lines": len(f.new_changed),
             "changed_functions": sorted(f.functions)}
            for f in self.files]}


# --------------------------------------------------------------- C functions

_IDENT_BEFORE_PAREN = re.compile(r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*$")
_NON_FUNC_KW = re.compile(r"\b(struct|union|enum|class|namespace|typedef)\b")


def _strip_code(text: str) -> str:
    """Blank out comments and string/char literals, preserving newlines/offsets."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "; i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "; i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
        elif c in "\"'":
            q = c; i += 1
            while i < n and text[i] != q and text[i] != "\n":
                if text[i] == "\\":
                    out[i] = " "; i += 1
                    if i < n and text[i] != "\n":
                        out[i] = " "
                    i += 1
                    continue
                out[i] = " "; i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def function_spans(text: str) -> list[tuple[str, int, int]]:
    """(name, first_line, last_line) of top-level function definitions."""
    code = _strip_code(text)
    # drop preprocessor lines (keep length)
    code = "\n".join(" " * len(l) if l.lstrip().startswith("#") else l
                     for l in code.split("\n"))
    spans = []
    depth = 0
    stmt_start = 0
    open_pos = None
    name = None
    line_of = lambda pos: code.count("\n", 0, pos) + 1
    for pos, ch in enumerate(code):
        if ch == "{":
            if depth == 0:
                header = code[stmt_start:pos]
                name = None
                if "(" in header and not _NON_FUNC_KW.search(header) \
                        and "=" not in header.split("(")[0]:
                    close = header.rfind(")")
                    if close != -1:
                        lvl, j = 0, close
                        while j >= 0:
                            if header[j] == ")":
                                lvl += 1
                            elif header[j] == "(":
                                lvl -= 1
                                if lvl == 0:
                                    break
                            j -= 1
                        m = _IDENT_BEFORE_PAREN.search(header[:max(j, 0)])
                        if m:
                            name = m.group(1)
                open_pos = stmt_start + (len(header) - len(header.lstrip()))
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
            if depth == 0:
                if name:
                    spans.append((name, line_of(open_pos), line_of(pos)))
                name = None
                stmt_start = pos + 1
        elif ch == ";" and depth == 0:
            stmt_start = pos + 1
    return spans


def _code_lines(lines: list[str]) -> list[str]:
    code = _strip_code("".join(lines)).split("\n")
    code = code[:len(lines)] + [""] * (len(lines) - len(code))
    return [" ".join(c.split()) for c in code]


def _functions_for(lines: set[int], spans) -> set[str]:
    out = set()
    for ln in lines:
        for name, s, e in spans:
            if s <= ln <= e:
                out.add(name)
    return out


# ------------------------------------------------------------------- helpers

def _is_text_file(path: str) -> bool:
    base = os.path.basename(path)
    _, ext = os.path.splitext(base)
    if base in _TEXT_NAMES or ext in _TEXT_EXT:
        try:
            with open(path, "rb") as fh:
                return b"\0" not in fh.read(8192)
        except OSError:
            return False
    return False


def _read_lines(path: str | None) -> list[str]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines(keepends=True)


def _rel_files(root: str) -> set[str]:
    out = set()
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            if _is_text_file(p):
                out.add(os.path.relpath(p, root))
    return out


def _attach_functions(fd: FileDiff, base_dir: str, patched_dir: str) -> None:
    old_text = "".join(_read_lines(os.path.join(base_dir, fd.relpath)))
    new_text = "".join(_read_lines(os.path.join(patched_dir, fd.relpath)))
    if old_text:
        fd.old_functions = _functions_for(fd.old_changed | fd.old_anchor, function_spans(old_text))
    if new_text:
        fd.new_functions = _functions_for(fd.new_changed | fd.new_anchor, function_spans(new_text))


# ------------------------------------------------------------------ generate

def generate(base_dir: str, patched_dir: str) -> Diff:
    diff = Diff(source="tree")
    raw_parts = []
    rels = sorted(_rel_files(base_dir) | _rel_files(patched_dir))
    for rel in rels:
        a = _read_lines(os.path.join(base_dir, rel))
        b = _read_lines(os.path.join(patched_dir, rel))
        if a == b:
            continue
        fd = FileDiff(relpath=os.path.normpath(rel))
        if not a:
            fd.status = "added"
        elif not b:
            fd.status = "removed"
        # Align on CODE (comments/literals blanked, whitespace collapsed) so
        # that comment-only or re-indentation edits do not count as changes to
        # the code the crash executes. Line numbering is preserved.
        na, nb = _code_lines(a), _code_lines(b)
        sm = difflib.SequenceMatcher(a=na, b=nb, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            if not any(na[i1:i2]) and not any(nb[j1:j2]):
                continue                            # only blank/comment lines moved
            old_real = {k + 1 for k in range(i1, i2) if na[k]}
            new_real = {k + 1 for k in range(j1, j2) if nb[k]}
            fd.old_changed.update(old_real)
            fd.new_changed.update(new_real)
            if not old_real and a:
                fd.old_anchor.update({max(1, i1), i1 + 1})
            if not new_real and b:
                fd.new_anchor.update({max(1, j1), j1 + 1})
        _attach_functions(fd, base_dir, patched_dir)
        diff.files.append(fd)
        raw_parts.append("".join(difflib.unified_diff(a, b, f"a/{rel}", f"b/{rel}", n=3)))
    diff.raw = "".join(raw_parts)
    return diff


# --------------------------------------------------------------------- parse

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _strip_path(p: str, strip: int) -> str | None:
    p = p.strip().split("\t")[0]
    if p == "/dev/null":
        return None
    parts = p.split("/")
    return os.path.normpath("/".join(parts[strip:])) if len(parts) > strip else os.path.normpath(p)


def parse(diff_text: str, base_dir: str | None = None, patched_dir: str | None = None,
          strip: int = 1) -> Diff:
    """Parse a unified diff; line numbers kept for BOTH sides."""
    diff = Diff(raw=diff_text, source="file")
    cur: FileDiff | None = None
    old_name = None
    old_ln = new_ln = 0
    for line in diff_text.splitlines():
        if line.startswith("--- "):
            old_name = _strip_path(line[4:], strip)
            continue
        if line.startswith("+++ "):
            new_name = _strip_path(line[4:], strip)
            rel = new_name or old_name
            cur = FileDiff(relpath=rel,
                           status="added" if old_name is None else
                                  ("removed" if new_name is None else "modified"))
            diff.files.append(cur)
            continue
        m = _HUNK_RE.match(line)
        if m and cur is not None:
            old_ln, new_ln = int(m.group(1)), int(m.group(3))
            continue
        if cur is None or line.startswith("\\"):
            continue
        if line.startswith("+"):
            cur.new_changed.add(new_ln)
            cur.old_anchor.update({max(1, old_ln - 1), old_ln})
            new_ln += 1
        elif line.startswith("-"):
            cur.old_changed.add(old_ln)
            cur.new_anchor.update({max(1, new_ln - 1), new_ln})
            old_ln += 1
        else:
            old_ln += 1
            new_ln += 1
    if base_dir and patched_dir:
        for fd in diff.files:
            _attach_functions(fd, base_dir, patched_dir)
    return diff
