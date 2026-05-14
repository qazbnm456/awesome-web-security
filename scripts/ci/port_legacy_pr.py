#!/usr/bin/env python3
"""
port_legacy_pr.py — Local helper to port a legacy README-shape PR
into the YAML data model.

Usage:
    python3 scripts/ci/port_legacy_pr.py <PR_NUMBER>

Reads the PR diff via `gh pr diff <N>`, extracts title/URL/description
from the added README list items, and prints a YAML entry stub (one per
new line found) to stdout. The human reviewer fills in the judgment
fields (category, type, difficulty, author) before pushing to the
contributor's branch.

The script is read-only: it does not touch the working tree, does not
push, does not modify any files. It exists to remove the mechanical
toil from porting; the merge decision stays human.

Output also includes a `Co-authored-by:` trailer ready for the eventual
squash-merge commit body, preserving full credit attribution to the
original contributor.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

REPO = "qazbnm456/awesome-web-security"

# Matches an added markdown list-item entry, e.g.
#   +- [Title](https://example.com) - One-line description.
# We accept the loose form where the leading dash is right against `+`
# (the typical github-flavored diff) and tolerate a missing description.
ADDED_ENTRY_RE = re.compile(
    r"^\+\s*-\s*\[([^\]]+)\]\(([^)]+)\)\s*(?:[-—]\s*(.+?))?\s*$"
)

SECTION_HEADER_RE = re.compile(r"^(#{2,4})\s+(.+?)\s*$")

# Loose detector: any added list item, even if the strict regex can't
# parse it (e.g. broken markdown like `[Title]([url1](url2))`).
LOOSE_LIST_RE = re.compile(r"^\+\s*-\s*\[")


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:60]


def get_pr_metadata(pr_num: int) -> dict:
    out = run([
        "gh", "pr", "view", str(pr_num), "-R", REPO,
        "--json", "number,author,title,headRefName",
    ])
    return json.loads(out)


def get_pr_diff(pr_num: int) -> str:
    return run(["gh", "pr", "diff", str(pr_num), "-R", REPO])


def parse_diff(diff: str) -> tuple[list[dict], list[str]]:
    """Walk the diff and collect added list-item entries plus the nearest
    section header above each one (best-effort hint for category lookup).

    Returns (entries, unparsed_lines). An unparsed line is one that looked
    like an added list item (`+- [...`) but didn't match the strict
    title/URL/description shape — typically a broken markdown link. The
    caller surfaces these so the human knows nothing was silently dropped.
    """
    entries: list[dict] = []
    unparsed: list[str] = []
    in_readme = False
    current_section: str | None = None

    for raw in diff.splitlines():
        if raw.startswith("diff --git"):
            in_readme = "README.md" in raw and "README-" not in raw
            current_section = None
            continue
        if not in_readme:
            continue

        if raw.startswith("@@"):
            # Section info is hunk-local; reset and pick up any inline hint
            # from the second @@ slot (rare for markdown but harmless).
            current_section = None
            m = re.match(r"@@[^@]+@@\s*(.+)", raw)
            if m and m.group(1).strip():
                current_section = m.group(1).strip()
            continue

        if raw and raw[0] in " +":
            body = raw[1:].rstrip()
            sh = SECTION_HEADER_RE.match(body)
            if sh:
                current_section = sh.group(2)

        if raw.startswith("+") and not raw.startswith("+++"):
            m = ADDED_ENTRY_RE.match(raw)
            if m:
                title = m.group(1).strip()
                url = m.group(2).strip()
                desc = (m.group(3) or "").strip().rstrip(".")
                entries.append({
                    "title": title,
                    "url": url,
                    "description": desc,
                    "section_hint": current_section,
                })
            elif LOOSE_LIST_RE.match(raw):
                unparsed.append(raw[1:].rstrip())

    return entries, unparsed


def coauthor_trailer(author_login: str) -> str:
    """Build the GitHub-noreply Co-authored-by trailer.

    GitHub recognises both the `id+login@users.noreply.github.com` form
    (matches the contributor to their profile precisely) and the bare
    `login@users.noreply.github.com` form. Prefer the id form."""
    try:
        uid = run(["gh", "api", f"users/{author_login}", "--jq", ".id"]).strip()
        return f"Co-authored-by: {author_login} <{uid}+{author_login}@users.noreply.github.com>"
    except subprocess.CalledProcessError:
        return f"Co-authored-by: {author_login} <{author_login}@users.noreply.github.com>"


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        print("Usage: port_legacy_pr.py <PR_NUMBER>", file=sys.stderr)
        return 2

    pr_num = int(sys.argv[1])

    meta = get_pr_metadata(pr_num)
    diff = get_pr_diff(pr_num)
    entries, unparsed = parse_diff(diff)

    author_login = meta["author"]["login"]

    print(f"# PR #{pr_num} — {meta['title']}")
    print(f"# Author: @{author_login}")
    print(f"# Found {len(entries)} entry/entries in README.md diff")
    if unparsed:
        print(f"# WARNING: {len(unparsed)} added list line(s) did not parse "
              f"(likely broken markdown). Inspect manually:")
        for line in unparsed:
            print(f"#   {line}")
    print()

    if not entries and not unparsed:
        print("# No added list-item entries detected. Inspect the diff manually:", file=sys.stderr)
        print(f"#   gh pr diff {pr_num} -R {REPO}", file=sys.stderr)
        return 1

    for i, e in enumerate(entries, 1):
        slug = slugify(e["title"])
        print(f"# --- Entry {i} of {len(entries)} ---")
        print(f"# section_hint (review!): {e['section_hint']}")
        print()
        print(f"  - id: <CATEGORY_KEY>-{slug}")
        print(f"    url: \"{e['url']}\"")
        print(f"    title: {e['title']}")
        print(f"    author:")
        print(f"      name: <FILL OR null>")
        print(f"      url: null")
        print(f"    category: <CATEGORY_KEY>  # candidate from hint: {e['section_hint']}")
        print(f"    type: <article|tool|cheatsheet|video|book|community|payload-list>")
        print(f"    languages: [en]")
        print(f"    difficulty: <intro|intermediate|advanced>")
        print(f"    date_added: \"<TODAY YYYY-MM-DD>\"")
        print(f"    archive_url: null")
        print(f"    last_checked: null")
        print(f"    fingerprint: null")
        print(f"    status: active")
        if e["description"]:
            print(f"    raw_rest: \"{e['description']}.\"")
        print()

    print("# --- Squash-merge trailer ---")
    print(f"# {coauthor_trailer(author_login)}")
    print(f"# Closes #{pr_num}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
