#!/usr/bin/env python3
"""Anchor preservation guard.

Compares the set of resolvable anchors in the working-tree README*.md against
the master baseline. Fails (exit 1) if any baseline anchor is missing from
the working tree; this would silently break external links pointing at
`#some-anchor`.

Resolvable anchors come from two sources:
  1. Explicit `<a name="..."></a>` tags before headings.
  2. GitHub's auto-anchor derived from `## Heading` / `### Heading` text.

Run from repo root: python3 scripts/verify_anchors.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
READMES = ["README.md", "README-zh.md", "README-jp.md"]
BASELINE_REF = "master"

ANCHOR_TAG_RE = re.compile(r'<a\s+name="([^"]+)">\s*</a>')
HEADING_RE = re.compile(r'^(#{2,4})\s+(.+?)\s*$', re.MULTILINE)


def github_auto_anchor(text: str) -> str:
    s = text.lower()
    s = re.sub(r"[`*_]", "", s)
    s = re.sub(r"[^a-z0-9\-\s]", "", s)
    s = re.sub(r"\s+", "-", s).strip("-")
    return s


def collect_anchors(text: str) -> set[str]:
    out: set[str] = set()
    for m in ANCHOR_TAG_RE.finditer(text):
        out.add(m.group(1))
    for m in HEADING_RE.finditer(text):
        out.add(github_auto_anchor(m.group(2)))
    return out


def read_baseline(path: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "show", f"{BASELINE_REF}:{path}"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return None


def main() -> int:
    failures: list[str] = []
    for fname in READMES:
        path = ROOT / fname
        if not path.exists():
            failures.append(f"{fname}: missing in working tree")
            continue
        current = collect_anchors(path.read_text(encoding="utf-8"))
        baseline_text = read_baseline(fname)
        if baseline_text is None:
            print(f"[skip] {fname}: no {BASELINE_REF} baseline (new file?)")
            continue
        baseline = collect_anchors(baseline_text)
        missing = baseline - current
        if missing:
            failures.append(
                f"{fname}: {len(missing)} anchor(s) missing vs {BASELINE_REF}:\n"
                + "\n".join(f"    - {a}" for a in sorted(missing))
            )

    if failures:
        sys.stderr.write("anchor verification FAILED\n\n")
        for f in failures:
            sys.stderr.write(f + "\n")
        return 1
    print("anchor verification: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
