#!/usr/bin/env python3
"""Generator: data/ -> README.md, README-zh.md, README-jp.md, data/index.json.

Reads data/categories.yml + data/entries/*.yml and emits the three language
READMEs plus a denormalized JSON index for downstream agents.

Run from repo root: python3 scripts/generate.py
"""
from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
ENTRIES_DIR = DATA_DIR / "entries"
CATEGORIES_FILE = DATA_DIR / "categories.yml"
TEMPLATES_DIR = DATA_DIR / "templates"
INDEX_FILE = DATA_DIR / "index.json"

LANGS = ("en", "zh", "jp")
LANG_SUFFIX = {"en": "", "zh": " - ZH", "jp": " - JP"}
LANG_FILE = {"en": "README.md", "zh": "README-zh.md", "jp": "README-jp.md"}
SCHEMA_VERSION = "1"


# ---------------------------------------------------------------------------
# Minimal YAML reader (no PyYAML dep)
# ---------------------------------------------------------------------------

class YamlError(Exception):
    pass


def yaml_decode_scalar(s: str):
    """Decode a YAML scalar (limited subset: null/bool/int/float/str)."""
    t = s.strip()
    if t == "" or t == "~" or t == "null":
        return None
    if t == "true":
        return True
    if t == "false":
        return False
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        # JSON-compatible double-quote unescape; single-quoted just strips quotes
        if t.startswith('"'):
            return json.loads(t)
        return t[1:-1].replace("''", "'")
    # try int
    if re.match(r"^-?\d+$", t):
        return int(t)
    # try float
    if re.match(r"^-?\d+\.\d+$", t):
        return float(t)
    # flow list: [a, b, c]
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        # naive split on commas not inside brackets/quotes
        out = []
        depth = 0
        cur = ""
        for c in inner:
            if c in "[\"'":
                depth += 1
            elif c in "]\"'":
                depth -= 1
            if c == "," and depth == 0:
                out.append(yaml_decode_scalar(cur))
                cur = ""
            else:
                cur += c
        if cur.strip():
            out.append(yaml_decode_scalar(cur))
        return out
    return t


def parse_yaml(text: str):
    """Parse a constrained YAML subset: top-level key with list of dicts.

    Supports nested 'author' sub-block. Handles indent of 2 spaces.
    """
    lines = text.split("\n")
    # state machine: top-level key -> list of records
    top: dict = {}
    cur_top_key: str | None = None
    cur_list: list | None = None
    cur_record: dict | None = None
    sub_block_name: str | None = None
    sub_block: dict | None = None

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        # detect indent
        stripped = raw.rstrip()
        leading = len(raw) - len(raw.lstrip(" "))

        # top-level key
        if leading == 0:
            m = re.match(r"^([A-Za-z_][\w\-]*):\s*(.*)$", stripped)
            if m:
                key = m.group(1)
                value = m.group(2)
                if value == "":
                    cur_top_key = key
                    cur_list = []
                    top[key] = cur_list
                    cur_record = None
                    sub_block_name = None
                else:
                    top[key] = yaml_decode_scalar(value)
                    cur_top_key = None
                    cur_list = None
                continue

        # list item marker "  - key: value"
        m = re.match(r"^( +)- ([A-Za-z_][\w\-]*):\s*(.*)$", raw)
        if m:
            ind = len(m.group(1))
            key = m.group(2)
            val = m.group(3)
            if cur_list is not None and ind == 2:
                cur_record = {}
                cur_list.append(cur_record)
                if val == "":
                    # might open a sub-block on next lines
                    cur_record[key] = None
                    sub_block_name = key
                    sub_block = None
                else:
                    cur_record[key] = yaml_decode_scalar(val)
                    sub_block_name = None
                continue

        # record field "    key: value"
        m = re.match(r"^( +)([A-Za-z_][\w\-]*):\s*(.*)$", raw)
        if m:
            ind = len(m.group(1))
            key = m.group(2)
            val = m.group(3)
            if cur_record is not None:
                if ind == 4:
                    if val == "":
                        # sub-block (object) starting
                        sub_block_name = key
                        sub_block = {}
                        cur_record[key] = sub_block
                    else:
                        cur_record[key] = yaml_decode_scalar(val)
                        sub_block_name = None
                elif ind == 6 and sub_block is not None and sub_block_name and cur_record.get(sub_block_name) is sub_block:
                    sub_block[key] = yaml_decode_scalar(val)
                # other indents ignored (unsupported)
    return top


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_categories() -> list[dict]:
    return parse_yaml(CATEGORIES_FILE.read_text(encoding="utf-8")).get("sections", [])


def load_all_entries() -> list[dict]:
    out: list[dict] = []
    for fp in sorted(ENTRIES_DIR.glob("*.yml")):
        data = parse_yaml(fp.read_text(encoding="utf-8"))
        for e in data.get("entries", []):
            out.append(e)
    return out


def load_template(name: str) -> str:
    return (TEMPLATES_DIR / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def entry_line(entry: dict) -> str:
    """Render one entry as a markdown bullet."""
    title = entry["title"]
    url = entry["url"]
    rest = entry.get("raw_rest")
    if rest:
        # Preserve original "rest" text -- handles multi-author and edge phrasings
        if rest.endswith("."):
            return f"- [{title}]({url}) - {rest}"
        return f"- [{title}]({url}) - {rest}."
    # Build a default "Written by [Name](url)." line
    author = entry.get("author")
    if isinstance(author, dict) and author.get("name"):
        name = author["name"]
        aurl = author.get("url")
        if aurl:
            return f"- [{title}]({url}) - Written by [{name}]({aurl})."
        return f"- [{title}]({url}) - Written by {name}."
    return f"- [{title}]({url})"


def section_heading(sec: dict) -> str:
    hashes = "#" * sec["h_level"]
    lines: list[str] = []
    if sec.get("anchor_tag"):
        lines.append(f'<a name="{sec["anchor_tag"]}"></a>')
    lines.append(f'{hashes} {sec["title"]}')
    return "\n".join(lines)


def render_toc(sections: list[dict]) -> str:
    lines = ["## Contents", ""]
    # nesting: top-level h_level==2 with in_toc, children of h_level 3 indented under their parent
    # We walk in order, tracking last-seen parent path
    for sec in sections:
        if not sec.get("in_toc"):
            continue
        anchor = sec.get("toc_anchor") or sec.get("anchor_tag") or ""
        label = sec.get("toc_label") or sec.get("title")
        h = int(sec["h_level"])
        # indent level: h2 -> 0, h3 -> 1, h4 -> 2
        indent = "  " * (h - 2)
        lines.append(f"{indent}- [{label}](#{anchor})")
    lines.append("")
    return "\n".join(lines)


def entry_matches_lang(entry: dict, lang: str) -> bool:
    """True if this entry should appear in the README for `lang`.

    An entry with `languages: [universal]` matches every language (it is
    rendered in all three READMEs). Otherwise the lang must be in the
    explicit list.
    """
    langs = entry.get("languages") or []
    return lang in langs or "universal" in langs


def render_section(sec: dict, entries: list[dict], lang: str) -> str:
    """Render a section heading + filtered entries for the given language."""
    matching = [e for e in entries if e.get("category") == sec["key"]
                and entry_matches_lang(e, lang)
                and e.get("status", "active") == "active"]
    # Skip empty sections that aren't structural containers.
    # A section is a "container" if it has any descendant section with entries.
    out: list[str] = []
    out.append(section_heading(sec))
    out.append("")
    if matching:
        # Sort by date_added asc, then by title
        matching.sort(key=lambda e: (e.get("date_added") or "9999-12-31", (e.get("title") or "").lower()))
        for entry in matching:
            out.append(entry_line(entry))
        out.append("")
    return "\n".join(out)


def has_descendants_with_entries(sec_key: str, sections: list[dict], entries_by_cat: dict[str, list[dict]], lang: str) -> bool:
    for s in sections:
        if s.get("parent") == sec_key:
            if any(entry_matches_lang(e, lang) for e in entries_by_cat.get(s["key"], [])):
                return True
            if has_descendants_with_entries(s["key"], sections, entries_by_cat, lang):
                return True
    return False


def render_readme(lang: str, sections: list[dict], entries: list[dict]) -> str:
    preamble = load_template("preamble.md")
    postamble = load_template("postamble.md")
    title_suffix = LANG_SUFFIX[lang]
    out: list[str] = []
    out.append(preamble.replace("{title_suffix}", title_suffix))
    out.append(render_toc(sections))

    entries_by_cat: dict[str, list[dict]] = {}
    for e in entries:
        entries_by_cat.setdefault(e.get("category", ""), []).append(e)

    # render each section in order
    skip_keys = {"code-of-conduct", "license"}
    for sec in sections:
        if sec["key"] in skip_keys:
            continue
        # Skip a section if it has no entries for this lang AND no descendants with entries
        # AND no explicit anchor_tag (anchors with no content must still be emitted
        # to preserve external links pointing at them).
        own = entries_by_cat.get(sec["key"], [])
        own_match = [e for e in own if entry_matches_lang(e, lang)]
        has_kids = has_descendants_with_entries(sec["key"], sections, entries_by_cat, lang)
        if not own_match and not has_kids and not sec.get("anchor_tag"):
            continue
        out.append(render_section(sec, entries, lang))

    out.append(postamble)
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

def build_index(sections: list[dict], entries: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "categories": [
            {
                "key": s["key"],
                "title": s["title"],
                "h_level": s.get("h_level"),
                "parent": s.get("parent"),
                "anchor": s.get("anchor_tag") or s.get("toc_anchor"),
            }
            for s in sections
            if s.get("in_toc") or s.get("parent")
        ],
        "entries": [
            {
                "id": e.get("id"),
                "url": e.get("url"),
                "title": e.get("title"),
                "author": e.get("author"),
                "category": e.get("category"),
                "type": e.get("type"),
                "languages": e.get("languages"),
                "difficulty": e.get("difficulty"),
                "date_added": e.get("date_added"),
                "archive_url": e.get("archive_url"),
                "last_checked": e.get("last_checked"),
                "status": e.get("status", "active"),
            }
            for e in entries
            if e.get("status", "active") != "quarantined"
        ],
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    print("[1/3] Loading data...")
    sections = load_categories()
    entries = load_all_entries()
    print(f"      sections={len(sections)} entries={len(entries)}")

    print("[2/3] Rendering READMEs...")
    for lang in LANGS:
        out = render_readme(lang, sections, entries)
        path = ROOT / LANG_FILE[lang]
        path.write_text(out, encoding="utf-8")
        print(f"      {LANG_FILE[lang]}: {len(out)} bytes")

    print("[3/3] Writing data/index.json...")
    idx = build_index(sections, entries)
    INDEX_FILE.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"      index.json: {len(idx['entries'])} entries, {len(idx['categories'])} categories")

    return 0


if __name__ == "__main__":
    sys.exit(main())
