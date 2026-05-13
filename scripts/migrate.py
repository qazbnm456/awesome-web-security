#!/usr/bin/env python3
"""One-shot migrator: README*.md -> data/categories.yml + data/entries/*.yml.

Parses README.md as the structural authority, then walks all three language
READMEs to collect entries. Entries are merged by URL: a single canonical
record carries a `languages` list covering every README it appears in.

Run from repo root: python3 scripts/migrate.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README_EN = ROOT / "README.md"
README_ZH = ROOT / "README-zh.md"
README_JP = ROOT / "README-jp.md"
DATA_DIR = ROOT / "data"
ENTRIES_DIR = DATA_DIR / "entries"
CATEGORIES_FILE = DATA_DIR / "categories.yml"
ERRORS_FILE = DATA_DIR / "migration-errors.md"


# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------

ANCHOR_RE = re.compile(r'^<a\s+name="([^"]+)"></a>\s*$')
HEADING_RE = re.compile(r'^(#{2,4})\s+(.+?)\s*$')
TOC_LINE_RE = re.compile(r'^(\s*)-\s+\[(?P<label>[^\]]+)\]\(#(?P<anchor>[^)]+)\)\s*$')
# Entry: -  [Title](url) - rest
# Title may contain escaped brackets; URL stops at first ')' that's not nested.
ENTRY_RE = re.compile(
    r'^-\s+\[(?P<title>.+?)\]\((?P<url>\S+?)\)\s*[-:.,]?\s*(?P<rest>.*?)\s*$'
)
# Author from rest: "Written by [Name](url)" / "Written by [Name](url) and [Name2](url2)" / variants
AUTHOR_LINK_RE = re.compile(r'\[(?P<name>[^\]]+)\]\((?P<url>[^)]+)\)')
AUTHOR_PLAIN_RE = re.compile(r'(?:Written\s+by|by|from)\s+(?P<rest>.+)', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Section:
    key: str                # unique stable id
    title: str              # heading text (preserves typos like "Cheetsheets")
    h_level: int            # 2|3|4
    anchor_tag: str | None  # value of <a name="..."> if present
    toc_label: str | None   # text shown in ToC
    toc_anchor: str | None  # anchor used in ToC link (may differ from anchor_tag)
    in_toc: bool
    parent: str | None      # parent section key
    order: int              # position in README

    def to_yaml(self) -> str:
        fields = []
        fields.append(f"key: {self.key}")
        fields.append(f"title: {yaml_str(self.title)}")
        fields.append(f"h_level: {self.h_level}")
        fields.append(f"anchor_tag: {yaml_str(self.anchor_tag)}")
        fields.append(f"toc_label: {yaml_str(self.toc_label)}")
        fields.append(f"toc_anchor: {yaml_str(self.toc_anchor)}")
        fields.append(f"in_toc: {str(self.in_toc).lower()}")
        fields.append(f"parent: {yaml_str(self.parent)}")
        return "  - " + "\n    ".join(fields)


@dataclass
class Entry:
    url: str
    title: str
    author_name: str | None = None
    author_url: str | None = None
    category: str = ""           # section key
    languages: list[str] = field(default_factory=list)
    date_added: str = ""
    raw_rest: str = ""           # original "rest of line" preserved for re-emit

    def normalized_url(self) -> str:
        u = self.url.strip()
        u = u.rstrip('/')
        return u.lower()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def yaml_str(s):
    """Emit a YAML scalar for str/None/bool."""
    if s is None:
        return "null"
    if isinstance(s, bool):
        return "true" if s else "false"
    s = str(s)
    if s == "":
        return '""'
    # quote if contains any YAML special / leading-whitespace / starts-with-digit
    if (re.search(r'[:#\n"\'{}\[\],&*?|<>=!%@`\\]', s)
            or s != s.strip()
            or s.lower() in ("null", "true", "false", "yes", "no", "on", "off", "~")
            or re.match(r'^[\-+\d]', s)):
        return json.dumps(s, ensure_ascii=False)
    return s


def slugify(text: str, max_len: int = 60) -> str:
    s = text.lower()
    s = re.sub(r"['\"`]+", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    s = s[:max_len].rstrip("-")
    return s or "entry"


def github_auto_anchor(heading_text: str) -> str:
    """Approximate GitHub's heading-to-anchor conversion.

    GitHub lowercases, drops non-alphanumeric (except hyphen + space), and
    replaces spaces with hyphens. Multiple consecutive hyphens are NOT
    collapsed (so "XSS - Foo" -> "xss---foo").
    """
    s = heading_text.lower()
    s = re.sub(r"[`*_]", "", s)
    # drop anything that isn't alnum, hyphen, or whitespace
    s = re.sub(r"[^a-z0-9\-\s]", "", s)
    # whitespace runs -> single hyphen (matches GitHub: "  " -> "-" still)
    s = re.sub(r"\s+", "-", s)
    s = s.strip("-")
    return s


def git_blame_dates(file_path: Path) -> dict[int, str]:
    """Map 1-based line_number -> ISO date (YYYY-MM-DD) via git blame."""
    try:
        out = subprocess.run(
            ["git", "blame", "--line-porcelain", "--", str(file_path.relative_to(ROOT))],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        print(f"git blame failed for {file_path}: {exc.stderr}", file=sys.stderr)
        return {}
    dates: dict[int, str] = {}
    cur_final_line: int | None = None
    cur_author_time: int | None = None
    for raw in out.splitlines():
        m = re.match(r"^[0-9a-f]{40}\s+\d+\s+(\d+)(?:\s+\d+)?$", raw)
        if m:
            cur_final_line = int(m.group(1))
            cur_author_time = None
            continue
        m = re.match(r"^author-time (\d+)$", raw)
        if m:
            cur_author_time = int(m.group(1))
        # blame ends a record with "\t<content>"; commit blocks alternate
        if raw.startswith("\t") and cur_final_line is not None and cur_author_time is not None:
            dates[cur_final_line] = datetime.fromtimestamp(
                cur_author_time, tz=timezone.utc
            ).strftime("%Y-%m-%d")
    return dates


def parse_authors(rest: str) -> tuple[str | None, str | None]:
    """Return (author_name, author_url) from the trailing portion of an entry."""
    if not rest:
        return None, None
    # find first markdown link after "Written by"/"by"
    after = rest
    m = AUTHOR_PLAIN_RE.search(rest)
    if m:
        after = m.group("rest")
    link = AUTHOR_LINK_RE.search(after)
    if link:
        return link.group("name").strip(), link.group("url").strip()
    # fall back: pure text author with no link
    plain = re.sub(r"\.+\s*$", "", after).strip()
    plain = re.sub(r"^@", "", plain)
    if plain and not plain.lower().startswith(("various", "and")):
        return plain[:80], None
    return None, None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

@dataclass
class ParsedReadme:
    sections: list[Section]               # in EN only; zh/jp inherit
    section_by_key: dict[str, Section]
    entries_by_section: dict[str, list[Entry]]
    unmatched_lines: list[tuple[int, str]]


def parse_toc(lines: list[str]) -> list[tuple[str, str, int]]:
    """Returns list of (label, anchor, indent_level) for ToC entries."""
    toc: list[tuple[str, str, int]] = []
    in_toc = False
    for line in lines:
        if line.strip().startswith("## Contents"):
            in_toc = True
            continue
        if in_toc:
            if line.startswith("## ") and not line.startswith("## Contents"):
                break
            m = TOC_LINE_RE.match(line)
            if m:
                indent = len(m.group(1)) // 2
                toc.append((m.group("label"), m.group("anchor"), indent))
    return toc


def parse_readme(file_path: Path, structure: list[Section] | None = None) -> ParsedReadme:
    """Parse a README. If `structure` is provided, reuse it; otherwise infer from EN.

    Section assignment for entries is by *position*: an entry line belongs to
    the most recent section heading above it.
    """
    raw = file_path.read_text(encoding="utf-8")
    lines = raw.split("\n")
    blame = git_blame_dates(file_path)

    sections: list[Section] = []
    section_by_key: dict[str, Section] = {}
    entries_by_section: dict[str, list[Entry]] = {}
    unmatched: list[tuple[int, str]] = []

    toc = parse_toc(lines)
    toc_by_label: dict[str, tuple[str, int]] = {}
    for label, anchor, indent in toc:
        toc_by_label.setdefault(label, (anchor, indent))
    toc_by_anchor: dict[str, tuple[str, int]] = {a: (label, indent) for label, a, indent in toc}

    pending_anchor: str | None = None
    current_section_key: str | None = None
    parent_stack: list[tuple[int, str]] = []   # (h_level, section_key)
    order = 0

    def make_section_key(title: str, parent: str | None) -> str:
        # Special cases for unwieldy / ambiguous titles
        if parent == "browser-exploitation":
            if title.lower().startswith("frontend"):
                return "browser-frontend"
            if title.lower().startswith("backend"):
                return "browser-backend"
        base = slugify(title)
        if parent in ("evasions", "tricks", "pocs", "tools", "practices"):
            if not base.startswith(parent + "-"):
                return f"{parent}-{base}"
        if parent in ("tools-reconnaissance", "tools-offensive"):
            if base.startswith("tools-"):
                return base
            return f"tools-{base}"
        return base

    for idx, line in enumerate(lines):
        line_no = idx + 1

        am = ANCHOR_RE.match(line)
        if am:
            pending_anchor = am.group(1)
            continue

        hm = HEADING_RE.match(line)
        if hm:
            h_level = len(hm.group(1))
            title = hm.group(2).strip()
            # Skip the Contents heading itself
            if title.lower() == "contents":
                pending_anchor = None
                continue

            # Pop parent stack until we find a level less than this
            while parent_stack and parent_stack[-1][0] >= h_level:
                parent_stack.pop()
            parent_key = parent_stack[-1][1] if parent_stack else None

            if structure is None:
                # EN: build sections
                # Special-case keys to match expected anchors / nesting
                if pending_anchor:
                    key = pending_anchor
                else:
                    key = make_section_key(title, parent_key)

                # Determine toc_label / toc_anchor from parsed ToC
                # Strategy: search for an exact label match first, then fallback to anchor-based
                toc_label = title
                toc_anchor = pending_anchor or github_auto_anchor(title)
                in_toc = False
                # If pending_anchor is in toc map, use that anchor
                if pending_anchor and pending_anchor in toc_by_anchor:
                    toc_label = toc_by_anchor[pending_anchor][0]
                    toc_anchor = pending_anchor
                    in_toc = True
                else:
                    # try matching by the auto-anchor of this heading
                    auto = github_auto_anchor(title)
                    if auto in toc_by_anchor:
                        toc_label = toc_by_anchor[auto][0]
                        toc_anchor = auto
                        in_toc = True

                order += 1
                sec = Section(
                    key=key,
                    title=title,
                    h_level=h_level,
                    anchor_tag=pending_anchor,
                    toc_label=toc_label if in_toc else None,
                    toc_anchor=toc_anchor if in_toc else None,
                    in_toc=in_toc,
                    parent=parent_key,
                    order=order,
                )
                sections.append(sec)
                section_by_key[key] = sec
                entries_by_section.setdefault(key, [])

                parent_stack.append((h_level, key))
                current_section_key = key
            else:
                # zh/jp: locate section by heading position relative to structure
                # We assume the same section order; advance index in structure.
                # Find next section with matching title or h_level.
                match_key = None
                for sec in structure:
                    if sec.title == title and sec.h_level == h_level:
                        match_key = sec.key
                        break
                if match_key is None:
                    # try fuzzy: same h_level + any title containing core word
                    for sec in structure:
                        if sec.h_level == h_level and slugify(sec.title) == slugify(title):
                            match_key = sec.key
                            break
                if match_key is None:
                    # unknown section in zh/jp -- skip but log
                    unmatched.append((line_no, f"[unknown section] {h_level} {title}"))
                    current_section_key = None
                else:
                    current_section_key = match_key
                    entries_by_section.setdefault(match_key, [])
                    parent_stack.append((h_level, match_key))

            pending_anchor = None
            continue

        # Entry line?
        if line.strip().startswith("- ") and current_section_key:
            em = ENTRY_RE.match(line)
            if em:
                title_t = em.group("title").strip()
                url_t = em.group("url").strip()
                rest_t = em.group("rest") or ""
                if url_t.startswith("#"):
                    # ToC line that slipped through
                    continue
                a_name, a_url = parse_authors(rest_t)
                entries_by_section[current_section_key].append(Entry(
                    url=url_t,
                    title=title_t,
                    author_name=a_name,
                    author_url=a_url,
                    category=current_section_key,
                    languages=[],
                    date_added=blame.get(line_no, ""),
                    raw_rest=rest_t,
                ))
            else:
                unmatched.append((line_no, line))
            pending_anchor = None
            continue

        # ignore everything else (paragraphs, separators, badges)
        pending_anchor = None

    return ParsedReadme(
        sections=sections,
        section_by_key=section_by_key,
        entries_by_section=entries_by_section,
        unmatched_lines=unmatched,
    )


# ---------------------------------------------------------------------------
# Merge across languages
# ---------------------------------------------------------------------------

LANG_FILES = [("en", README_EN), ("zh", README_ZH), ("jp", README_JP)]


def merge_entries(parses: dict[str, ParsedReadme]) -> tuple[dict[str, list[Entry]], list[str]]:
    """Merge per-language parses into a single category -> [Entry] map."""
    canonical: dict[tuple[str, str], Entry] = {}    # (section_key, normalized_url) -> Entry
    notes: list[str] = []

    for lang in ("en", "zh", "jp"):
        parse = parses[lang]
        for section_key, entries in parse.entries_by_section.items():
            for entry in entries:
                key = (section_key, entry.normalized_url())
                if key in canonical:
                    canon = canonical[key]
                    if lang not in canon.languages:
                        canon.languages.append(lang)
                    # prefer earliest date
                    if entry.date_added and (
                        not canon.date_added or entry.date_added < canon.date_added
                    ):
                        canon.date_added = entry.date_added
                    # if EN provides better author info, keep canonical
                else:
                    entry.languages = [lang]
                    canonical[key] = entry

    grouped: dict[str, list[Entry]] = {}
    for (section_key, _), entry in canonical.items():
        grouped.setdefault(section_key, []).append(entry)

    for key in grouped:
        grouped[key].sort(key=lambda e: (e.date_added or "9999-12-31", e.title))

    return grouped, notes


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

TYPE_BY_SECTION: dict[str, str] = {}

def section_type(section_key: str) -> str:
    if section_key.startswith("tools-") or section_key == "social-engineering-database":
        return "tool"
    if section_key == "cheetsheets":
        return "cheatsheet"
    if section_key in ("twitter-users", "community"):
        return "community"
    if section_key == "blogs":
        return "article"
    return "article"


def entry_id(category: str, title: str, used: set[str]) -> str:
    base = f"{category}-{slugify(title, max_len=50)}"
    candidate = base
    n = 1
    while candidate in used:
        n += 1
        candidate = f"{base}-{n}"
    used.add(candidate)
    return candidate


def write_categories(sections: list[Section]) -> None:
    out = ["# Section structure for the awesome-web-security README.",
           "# Generated by scripts/migrate.py. Edit carefully: changes here propagate",
           "# to all three language READMEs through scripts/generate.py.",
           "",
           "sections:"]
    for sec in sections:
        out.append(f"  - key: {yaml_str(sec.key)}")
        out.append(f"    title: {yaml_str(sec.title)}")
        out.append(f"    h_level: {sec.h_level}")
        out.append(f"    anchor_tag: {yaml_str(sec.anchor_tag)}")
        out.append(f"    toc_label: {yaml_str(sec.toc_label)}")
        out.append(f"    toc_anchor: {yaml_str(sec.toc_anchor)}")
        out.append(f"    in_toc: {str(sec.in_toc).lower()}")
        out.append(f"    parent: {yaml_str(sec.parent)}")
    CATEGORIES_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")


def write_entries(grouped: dict[str, list[Entry]], sections: list[Section]) -> None:
    ENTRIES_DIR.mkdir(parents=True, exist_ok=True)
    used_ids: set[str] = set()
    # ensure a file per section (even if empty -- generator can handle)
    written_files: dict[str, list[str]] = {}

    for sec in sections:
        entries = grouped.get(sec.key, [])
        if not entries and not section_has_entries_in_any_lang(sec.key, grouped):
            continue
        type_default = section_type(sec.key)
        lines = [f"# Entries for section: {sec.title}",
                 f"# Auto-migrated by scripts/migrate.py. Edit individual fields freely.",
                 "",
                 "entries:"]
        for entry in entries:
            eid = entry_id(sec.key, entry.title, used_ids)
            lines.append(f"  - id: {yaml_str(eid)}")
            lines.append(f"    url: {yaml_str(entry.url)}")
            lines.append(f"    title: {yaml_str(entry.title)}")
            if entry.author_name or entry.author_url:
                lines.append(f"    author:")
                lines.append(f"      name: {yaml_str(entry.author_name)}")
                lines.append(f"      url: {yaml_str(entry.author_url)}")
            else:
                lines.append(f"    author: null")
            lines.append(f"    category: {yaml_str(sec.key)}")
            lines.append(f"    type: {type_default}")
            lines.append(f"    languages: [{', '.join(entry.languages)}]")
            lines.append(f"    difficulty: intermediate")
            lines.append(f"    date_added: {yaml_str(entry.date_added or '2017-01-29')}")
            lines.append(f"    archive_url: null")
            lines.append(f"    last_checked: null")
            lines.append(f"    fingerprint: null")
            lines.append(f"    status: active")
            if entry.raw_rest:
                # preserve original "rest" text in a notes-y field for round-trip fidelity
                lines.append(f"    raw_rest: {yaml_str(entry.raw_rest)}")
            else:
                lines.append(f"    raw_rest: null")
        out_path = ENTRIES_DIR / f"{sec.key}.yml"
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def section_has_entries_in_any_lang(key: str, grouped: dict[str, list[Entry]]) -> bool:
    return bool(grouped.get(key))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    # Safety guard: refuse to clobber a populated data/entries unless --force.
    if ENTRIES_DIR.exists():
        populated = [p for p in ENTRIES_DIR.glob("*.yml")]
        if len(populated) > 5 and "--force" not in sys.argv:
            print(
                f"refusing to re-run: {ENTRIES_DIR} already has {len(populated)} entry files.\n"
                f"  This is a ONE-SHOT importer. Re-running will overwrite hand-edits.\n"
                f"  If you really mean it, pass --force.",
                file=sys.stderr,
            )
            return 1

    print("[1/4] Parsing README.md (structural authority)...")
    en_parse = parse_readme(README_EN)
    print(f"      sections={len(en_parse.sections)} entries={sum(len(v) for v in en_parse.entries_by_section.values())}")

    print("[2/4] Parsing README-zh.md / README-jp.md...")
    zh_parse = parse_readme(README_ZH, structure=en_parse.sections)
    jp_parse = parse_readme(README_JP, structure=en_parse.sections)
    print(f"      zh entries={sum(len(v) for v in zh_parse.entries_by_section.values())}")
    print(f"      jp entries={sum(len(v) for v in jp_parse.entries_by_section.values())}")

    print("[3/4] Merging entries across languages by URL...")
    grouped, notes = merge_entries({"en": en_parse, "zh": zh_parse, "jp": jp_parse})
    print(f"      unique entries: {sum(len(v) for v in grouped.values())}")

    print("[4/4] Writing categories.yml + entries/*.yml...")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    write_categories(en_parse.sections)
    write_entries(grouped, en_parse.sections)

    # Migration errors / notes
    all_unmatched = []
    for lang, parse in (("en", en_parse), ("zh", zh_parse), ("jp", jp_parse)):
        for line_no, content in parse.unmatched_lines:
            all_unmatched.append(f"- `{lang}` line {line_no}: `{content[:120]}`")

    if all_unmatched or notes:
        ERRORS_FILE.write_text(
            "# Migration notes\n\n"
            "## Unmatched lines (entry parser could not classify)\n\n"
            + ("\n".join(all_unmatched) if all_unmatched else "_None._\n")
            + "\n\n## Notes from merge\n\n"
            + ("\n".join(f"- {n}" for n in notes) if notes else "_None._\n"),
            encoding="utf-8",
        )

    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
