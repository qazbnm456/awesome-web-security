#!/usr/bin/env python3
"""Schema validator for data/categories.yml and data/entries/*.yml.

Run from repo root: python3 scripts/verify_schema.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
ENTRIES_DIR = DATA_DIR / "entries"
CATEGORIES_FILE = DATA_DIR / "categories.yml"

# Reuse the parser from generate.py to keep one source of truth
sys.path.insert(0, str(ROOT / "scripts"))
from generate import parse_yaml  # noqa: E402

ENTRY_REQUIRED = ("id", "url", "title", "category", "type", "languages",
                  "difficulty", "date_added", "status")
# Fields that may appear on an entry but are not required.
ENTRY_OPTIONAL = ("author", "subcategory", "archive_url", "last_checked",
                  "fingerprint", "raw_rest", "notes", "archive_opt_out")
TYPE_VALUES = {"article", "tool", "cheatsheet", "video", "book", "community",
               "payload-list"}
LANG_VALUES = {"en", "zh", "jp", "tr", "universal"}
DIFFICULTY_VALUES = {"intro", "intermediate", "advanced"}
STATUS_VALUES = {"active", "dead", "archived-only", "quarantined"}
URL_RE = re.compile(r"^https?://")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def load_categories() -> dict[str, dict]:
    sections = parse_yaml(CATEGORIES_FILE.read_text(encoding="utf-8")).get("sections", [])
    return {s["key"]: s for s in sections}


def validate_entry(entry: dict, file_label: str, category_keys: set[str]) -> list[str]:
    errs: list[str] = []
    eid = entry.get("id", "<unknown>")
    for field in ENTRY_REQUIRED:
        if field not in entry or entry.get(field) is None:
            errs.append(f"{file_label}:{eid} missing required field `{field}`")

    if "id" in entry and isinstance(entry["id"], str) and not ID_RE.match(entry["id"]):
        errs.append(f"{file_label}:{eid} id is not kebab-case")

    if "url" in entry and isinstance(entry["url"], str) and not URL_RE.match(entry["url"]):
        errs.append(f"{file_label}:{eid} url must start with http(s)://")

    if "category" in entry and entry["category"] not in category_keys:
        errs.append(f"{file_label}:{eid} unknown category `{entry['category']}`")

    if "type" in entry and entry["type"] not in TYPE_VALUES:
        errs.append(f"{file_label}:{eid} invalid type `{entry['type']}` (allowed: {sorted(TYPE_VALUES)})")

    if "languages" in entry:
        langs = entry["languages"] or []
        if not isinstance(langs, list) or not langs:
            errs.append(f"{file_label}:{eid} languages must be a non-empty list")
        else:
            bad = [l for l in langs if l not in LANG_VALUES]
            if bad:
                errs.append(f"{file_label}:{eid} invalid languages: {bad} (allowed: {sorted(LANG_VALUES)})")

    if "difficulty" in entry and entry["difficulty"] not in DIFFICULTY_VALUES:
        errs.append(f"{file_label}:{eid} invalid difficulty `{entry['difficulty']}`")

    if "status" in entry and entry["status"] not in STATUS_VALUES:
        errs.append(f"{file_label}:{eid} invalid status `{entry['status']}`")

    if "date_added" in entry and isinstance(entry["date_added"], str) and not DATE_RE.match(entry["date_added"]):
        errs.append(f"{file_label}:{eid} date_added must be YYYY-MM-DD")

    if "archive_opt_out" in entry and not isinstance(entry["archive_opt_out"], bool):
        errs.append(f"{file_label}:{eid} archive_opt_out must be true or false, got {entry['archive_opt_out']!r}")

    return errs


def main() -> int:
    category_keys = set(load_categories().keys())
    if not category_keys:
        print("verify_schema: no categories loaded -- check data/categories.yml", file=sys.stderr)
        return 1

    seen_ids: dict[str, str] = {}
    failures: list[str] = []

    for fp in sorted(ENTRIES_DIR.glob("*.yml")):
        try:
            data = parse_yaml(fp.read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append(f"{fp.name}: parse failure: {exc}")
            continue
        entries = data.get("entries", [])
        for entry in entries:
            errs = validate_entry(entry, fp.name, category_keys)
            failures.extend(errs)
            eid = entry.get("id")
            if eid:
                if eid in seen_ids:
                    failures.append(f"{fp.name}: duplicate id `{eid}` (also in {seen_ids[eid]})")
                else:
                    seen_ids[eid] = fp.name

    if failures:
        sys.stderr.write("schema verification FAILED\n\n")
        for line in failures:
            sys.stderr.write(f"  - {line}\n")
        return 1

    print(f"schema verification: ok ({len(seen_ids)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
