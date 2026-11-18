"""Exact identification of the source a binary was built from.

`source_id(path)` returns:
  tree_sha256  deterministic hash over every file (relative path + bytes) in
               the version directory -- always available, even outside git
  git_commit   HEAD of the enclosing git repository, if any
  git_dirty    whether that directory has uncommitted changes relative to HEAD
  git_tree     git's object id of the directory at HEAD (if tracked)
"""

from __future__ import annotations

import hashlib
import os
import subprocess


def tree_sha256(root: str) -> str:
    h = hashlib.sha256()
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            h.update(rel.encode() + b"\0")
            with open(p, "rb") as fh:
                h.update(hashlib.sha256(fh.read()).digest())
    return h.hexdigest()


def _git(args, cwd):
    try:
        p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=15)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def source_id(path: str) -> dict:
    out = {"path": path, "tree_sha256": tree_sha256(path),
           "git_commit": None, "git_dirty": None, "git_tree": None}
    top = _git(["rev-parse", "--show-toplevel"], path)
    if top:
        out["git_commit"] = _git(["rev-parse", "HEAD"], path)
        rel = os.path.relpath(os.path.realpath(path), os.path.realpath(top))
        status = _git(["status", "--porcelain", "--", "."], path)
        out["git_dirty"] = bool(status)
        out["git_tree"] = _git(["rev-parse", f"HEAD:{rel}"], top) if rel != "." else \
            _git(["rev-parse", "HEAD^{tree}"], top)
    return out
