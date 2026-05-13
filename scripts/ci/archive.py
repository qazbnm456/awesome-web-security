#!/usr/bin/env python3
"""Submit newly-added entry URLs to Wayback Machine; backfill `archive_url`.

Walks data/entries/*.yml, finds entries where:
  - status == "active"
  - archive_url is null
  - archive_opt_out is not true

For each, calls Wayback's Save Page Now endpoint, parses the resulting
archive URL, and writes it back into the YAML file in-place. Caps per-run
volume (default 5) so a single merge doesn't burn Wayback rate limits.

Run from repo root: python3 scripts/ci/archive.py
"""
from __future__ import annotations

import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ENTRIES_DIR = ROOT / "data" / "entries"

WAYBACK_SAVE = "https://web.archive.org/save/"
WAYBACK_WEB = "https://web.archive.org"
MAX_PER_RUN = int(os.environ.get("ARCHIVE_MAX_PER_RUN", "5"))
PER_URL_TIMEOUT = int(os.environ.get("ARCHIVE_TIMEOUT", "90"))
USER_AGENT = "awesome-web-security-bot (+https://github.com/qazbnm456/awesome-web-security)"

# ---------------------------------------------------------------------------
# Minimal YAML field accessors — we mutate the file textually to keep
# the formatting Stable, rather than parse + re-emit.
# ---------------------------------------------------------------------------

ENTRY_START_RE = re.compile(r"^  - id:\s*(.+)$")
FIELD_RE = re.compile(r"^    ([A-Za-z_]+):\s*(.*)$")


def yaml_decode(s: str):
    t = s.strip()
    if t in ("", "null", "~"):
        return None
    if t == "true":
        return True
    if t == "false":
        return False
    if t.startswith('"') and t.endswith('"'):
        return t[1:-1].encode("utf-8").decode("unicode_escape")
    return t


def yaml_quote(s: str) -> str:
    """Quote a string for the same format generate.py uses."""
    if any(c in s for c in [':', '#', '"', "'", '\\', '\n', '|', '>']):
        import json as _json
        return _json.dumps(s, ensure_ascii=False)
    if any(c in s for c in [' ', '/', '+', '-', '@', '.', '(']):
        return f'"{s}"'
    return s


def parse_entries(path: Path) -> list[dict]:
    """Return list of dicts: each has line ranges for in-place edit."""
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    entries: list[dict] = []
    current: dict | None = None
    for idx, line in enumerate(lines):
        if line.startswith("  - id:"):
            if current is not None:
                current["end_line"] = idx - 1
                entries.append(current)
            m = ENTRY_START_RE.match(line)
            current = {"start_line": idx, "fields": {}, "field_lines": {}, "raw": lines}
            current["fields"]["id"] = m.group(1).strip()
            current["field_lines"]["id"] = idx
            continue
        if current is None:
            continue
        m = FIELD_RE.match(line)
        if m:
            key, val = m.group(1), m.group(2)
            current["fields"][key] = yaml_decode(val)
            current["field_lines"][key] = idx
    if current is not None:
        current["end_line"] = len(lines) - 1
        entries.append(current)
    return entries


def write_archive_url(path: Path, entry: dict, archive_url: str) -> None:
    """Update the `archive_url:` line for an entry in-place."""
    lines = entry["raw"]
    line_no = entry["field_lines"].get("archive_url")
    if line_no is None:
        # field not present; insert before status:
        insert_at = entry["field_lines"].get("status", entry["end_line"])
        new_line = f"    archive_url: {yaml_quote(archive_url)}"
        lines.insert(insert_at, new_line)
    else:
        lines[line_no] = f"    archive_url: {yaml_quote(archive_url)}"
    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Wayback
# ---------------------------------------------------------------------------

def archive_url_for(target_url: str) -> str | None:
    """Submit to Wayback's Save Page Now and return the resulting archive URL.

    Returns None on failure; caller leaves entry's archive_url as null and
    retries on next run.
    """
    save_url = WAYBACK_SAVE + target_url
    req = urllib.request.Request(
        save_url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
    )
    try:
        with urllib.request.urlopen(req, timeout=PER_URL_TIMEOUT) as resp:
            # Wayback returns the snapshot URL via the Content-Location header
            # when the archive is fresh, or via the final URL after redirects.
            cl = resp.headers.get("Content-Location") or ""
            if cl.startswith("/web/"):
                return WAYBACK_WEB + cl
            final = resp.url
            if "/web/" in final:
                # extract the canonical snapshot URL
                m = re.search(r"(/web/\d+/.+)$", final)
                if m:
                    return WAYBACK_WEB + m.group(1)
            return None
    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"[archive] HTTP {exc.code} for {target_url}\n")
        return None
    except Exception as exc:
        sys.stderr.write(f"[archive] {type(exc).__name__} for {target_url}: {exc}\n")
        return None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    if not ENTRIES_DIR.exists():
        print("data/entries not found; nothing to archive")
        return 0

    candidates: list[tuple[Path, dict]] = []
    for yml in sorted(ENTRIES_DIR.glob("*.yml")):
        for entry in parse_entries(yml):
            f = entry["fields"]
            if (f.get("status") in (None, "active")
                    and f.get("archive_url") is None
                    and f.get("archive_opt_out") is not True
                    and isinstance(f.get("url"), str)):
                candidates.append((yml, entry))

    if not candidates:
        print("no entries need archiving")
        return 0

    # Prioritize newest entries first so a brand-new entry gets archived on
    # the merge that introduces it. Older (migrated) entries gradually
    # backfill via subsequent runs.
    candidates.sort(
        key=lambda x: x[1]["fields"].get("date_added") or "1970-01-01",
        reverse=True,
    )

    take = candidates[:MAX_PER_RUN]
    skipped = len(candidates) - len(take)
    print(f"archiving {len(take)} entries this run ({skipped} deferred to next run)")

    archived = 0
    for yml_path, entry in take:
        url = entry["fields"]["url"]
        eid = entry["fields"]["id"]
        print(f"  {eid}: archiving {url} ...", end=" ", flush=True)
        result = archive_url_for(url)
        if result:
            # re-parse to get fresh line list (previous archives may have shifted lines)
            fresh = parse_entries(yml_path)
            target = next((e for e in fresh if e["fields"].get("id") == eid), None)
            if target is None:
                print("FAILED (entry vanished?)")
                continue
            write_archive_url(yml_path, target, result)
            print("ok")
            archived += 1
        else:
            print("failed (will retry next run)")
        # gentle pacing — Wayback can be slow per-URL
        time.sleep(2)

    print(f"\ndone: {archived}/{len(take)} archived")
    return 0


if __name__ == "__main__":
    sys.exit(main())
