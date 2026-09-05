#!/usr/bin/env python3
"""Find entries whose page is no longer the resource we listed.

`health-link-check.yml` asks whether a URL answers. That misses the failure
that actually happened here: `halbecaf.com` lapsed, someone re-registered it,
and a V8 exploitation writeup in Browser Backend became an Indonesian gambling
site. It answers 200. It will answer 200 forever. A status-code check is
structurally blind to it, and so is a redirect check — githubengineering.com
serves a meta-refresh, which reads as 200 too.

So this asks a different question: does the page still talk about the thing the
entry says it is? No stored baseline is needed, which matters because every
`fingerprint` field in the data is currently null.

Two signals, deliberately kept separate in the report:

  drift    — the entry's distinctive title words have largely vanished from the
             page. Suggestive, not conclusive: a repo README may never repeat
             its own title, and a heavily JS-rendered page yields little text.
  takeover — the page contains the vocabulary of an expired-domain grab
             (casino, slot, togel, pharmacy spam). One hit here is worth more
             than any amount of drift.

Report-only. It never edits `data/`, because the judgement of whether a page
has stopped being itself is not one to automate on a first pass.

Usage:
    python3 scripts/ci/check_content_drift.py [--limit N] [--workers 8]
        [--json out.json] [--category KEY]
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent.parent
INDEX = ROOT / "data" / "index.json"

MAX_BYTES = 300_000
# Below this a page told us nothing; used to tell "short" from "JS-rendered".
MIN_TEXT_CHARS = 400
TIMEOUT = 25
UA = "Mozilla/5.0 awesome-web-security-health"

# Statuses that mean "the host is up and refused automation", not "gone".
BLOCKED_STATUSES = frozenset({401, 403, 405, 407, 429, 503, 521, 522, 523, 526})

# Vocabulary that does not appear on a web-security page by accident. Kept
# short and specific: broad words like "free" or "download" would fire on half
# the list. Each term is one an expired-domain grab actually uses.
TAKEOVER_TERMS = (
    "togel", "slot gacor", "situs slot", "judi", "bandar", "casino", "kasino",
    "poker online", "bet88", "sbobet", "rtp live", "maxwin", "pragmatic play",
    "escort", "viagra", "cialis", "canadian pharmacy", "payday loan",
)

_TAKEOVER_RE = {t: re.compile(r"\b" + re.escape(t) + r"\b") for t in TAKEOVER_TERMS}

# Words too common to identify anything.
# Entries that point at a site root or a person's blog. The title is the
# author or the publication ("l1nk3r's blog", "Orange"), which a homepage has
# no reason to print, so a low overlap there says nothing. Nine of the first
# run's drift hits were this.
HOMEPAGE_CATEGORIES = frozenset({"blogs", "forums", "digests", "twitter-users",
                                 "community", "social-engineering-database"})

STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "for", "on", "with", "at",
    "by", "from", "is", "it", "its", "as", "how", "i", "you", "your", "we",
    "what", "why", "when", "using", "use", "guide", "tutorial", "introduction",
    "part", "web", "security", "vulnerability", "attack", "attacks", "via",
}


def _host_check(host: str) -> str | None:
    """None when the host is safe to fetch, else the reason it is not.

    The first version folded DNS failure into "non-public host", which put a
    domain that no longer resolves — real decay, worth acting on — in the same
    bucket as an SSRF guard trip. Nineteen entries landed there and the report
    could not say which were which."""
    if not host:
        return "no host"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "dns does not resolve"
    except Exception:  # noqa: BLE001
        return "dns lookup failed"
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return "non-public address"
        except ValueError:
            return "unparseable address"
    return None


class _Text(HTMLParser):
    SKIP = {"script", "style", "svg", "noscript"}

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


# github.com/<owner>/<repo>, but the first path segment is not always an owner.
# `github.com/apps/guardrails` is a GitHub App listing; treating "apps" as an
# owner made the repo endpoint 404 and the entry was reported as a deleted
# repository. These are the reserved first segments that are not accounts.
_GH_RESERVED = ("apps", "marketplace", "orgs", "features", "topics", "sponsors",
                "collections", "explore", "settings", "enterprise", "security",
                "about", "pricing", "readme", "search", "login", "signup")
_GH_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?!(?:" + "|".join(_GH_RESERVED) + r")/)"
    r"([^/]+)/([^/#?]+?)(?:\.git)?"
    r"(?:/tree/[^/]+/(.+?))?/?(?:[#?].*)?$", re.IGNORECASE)


def _github_readme(url: str) -> tuple[str, str | None] | None:
    """github.com renders READMEs with JavaScript; read the markdown instead."""
    m = _GH_URL_RE.match(url)
    if not m:
        return None
    api = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/readme"
    if m.group(3):
        api += "/" + quote(unquote(m.group(3)))
    headers = {"Accept": "application/vnd.github+json", "User-Agent": UA}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        with urllib.request.urlopen(
                urllib.request.Request(api, headers=headers), timeout=TIMEOUT) as r:
            body = json.loads(r.read().decode())
        return base64.b64decode(body.get("content", "")).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return "", f"github api {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return "", f"github api {type(exc).__name__}"

    # A README 404 has two very different causes. Ask whether the repository
    # itself is still there: gone is real decay, present-without-a-README just
    # means read the HTML page like any other site.
    repo_api = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}"
    try:
        with urllib.request.urlopen(
                urllib.request.Request(repo_api, headers=headers), timeout=TIMEOUT):
            return None            # repo lives; fall through to the HTML fetch
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "", "github repo deleted"
        return "", f"github api {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return "", f"github api {type(exc).__name__}"


def fetch(url: str) -> tuple[str, str | None]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "", "non-http scheme"
    bad = _host_check(parsed.hostname or "")
    if bad:
        return "", bad
    gh = _github_readme(url)
    if gh is not None:
        return gh
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, headers={
                    "User-Agent": UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                }), timeout=TIMEOUT) as r:
            raw = r.read(MAX_BYTES)
    except urllib.error.HTTPError as exc:
        # A refusal is not a death. 403/429/521 and friends mean a server
        # answered and declined to serve automation — paper.seebug.org sits
        # behind a JS browser challenge and returns 521 to everything without
        # one. Reporting these as failures implies decay that is not there.
        kind = "blocked" if exc.code in BLOCKED_STATUSES else "HTTP"
        return "", f"{kind} {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return "", f"{type(exc).__name__}"
    # A PDF fed through an HTML parser yields tens of thousands of characters
    # of decoded binary and a title overlap of 0.00 — fourteen entries in the
    # first full run, every one of them a conference slide deck or a paper, and
    # every one a false positive. There is nothing to judge without a PDF
    # reader, and guessing from noise is worse than saying so.
    if raw[:5] == b"%PDF-":
        return "", "pdf (not extracted)"

    p = _Text()
    try:
        html = raw.decode("utf-8", "replace")
        p.feed(html)
    except Exception:  # noqa: BLE001
        return "", "parse error"
    text = " ".join(p.parts)
    # Distinguish "this page is short" from "this page is built by JavaScript".
    # Both leave the parser with nothing; only one is evidence about the entry.
    if len(text) < MIN_TEXT_CHARS and len(raw) > 20_000 and html.count("<script") >= 5:
        return text, "js-rendered (no text in the HTML)"
    return text, None


def terms(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]{3,}", text.lower()) if w not in STOP}


def assess(entry: dict) -> dict:
    url = entry.get("url") or ""
    text, err = fetch(url)
    out = {"id": entry.get("id"), "url": url, "category": entry.get("category"),
           "title": entry.get("title"), "chars": len(text), "error": err}
    if err:
        return out

    path = urlparse(url).path.strip("/")
    out["homepage"] = (not path) or entry.get("category") in HOMEPAGE_CATEGORIES

    low = text.lower()
    # Word boundaries are load-bearing. A bare substring test reported "cialis"
    # on nine healthy pages, because it sits inside "specialist".
    out["takeover_hits"] = sorted({t for t in TAKEOVER_TERMS if _TAKEOVER_RE[t].search(low)})

    # Does the page still mention what the entry claims it is? The author's
    # name counts: a repo README often states the author but never the title.
    if out["homepage"]:
        out["overlap"] = None          # not a meaningful question for this shape
        return out

    wanted = terms(entry.get("title") or "")
    author = ((entry.get("author") or {}).get("name") or "").lstrip("@")
    wanted |= terms(author)
    out["title_terms"] = len(wanted)
    if not wanted:
        out["overlap"] = None
        return out
    present = terms(low)
    out["overlap"] = round(len(wanted & present) / len(wanted), 2)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--category")
    ap.add_argument("--json")
    ap.add_argument("--drift-below", type=float, default=0.25,
                    help="flag when this share or less of the title's distinctive words survive")
    ap.add_argument("--min-chars", type=int, default=400,
                    help="below this the fetch told us nothing; report separately")
    args = ap.parse_args()

    entries = json.loads(INDEX.read_text())["entries"]
    entries = [e for e in entries
               if e.get("status", "active") == "active"
               and (e.get("url") or "").startswith(("http://", "https://"))]
    if args.category:
        entries = [e for e in entries if e.get("category") == args.category]
    if args.limit:
        entries = entries[:args.limit]

    print(f"checking {len(entries)} active entries with {args.workers} workers\n", flush=True)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(assess, entries))

    # Spam vocabulary on a page whose title still matches is comment spam, not a
    # takeover — pwndizzle's Blogspot post is intact under a pile of Polish
    # casino links. Only a low overlap means the entry's content is gone.
    hits = [r for r in rows if r.get("takeover_hits")]
    takeover = [r for r in hits if (r.get("overlap") or 0) < 0.5]
    spammed = [r for r in hits if (r.get("overlap") or 0) >= 0.5]
    blocked = [r for r in rows if (r.get("error") or "").startswith("blocked")]
    unreadable = [r for r in rows if (r.get("error") or "").startswith(("pdf ", "js-rendered"))]
    errors = [r for r in rows if r.get("error") and r not in blocked and r not in unreadable]
    homepages = [r for r in rows if r.get("homepage") and not r.get("error")]
    thin = [r for r in rows if not r.get("error") and r["chars"] < args.min_chars]
    drift = [r for r in rows
             if not r.get("error") and r["chars"] >= args.min_chars
             and r.get("overlap") is not None and r["overlap"] <= args.drift_below
             and not r.get("takeover_hits")]
    flagged = (len(takeover) + len(spammed) + len(drift) + len(thin)
               + len(errors) + len(blocked) + len(unreadable))

    def show(title, items, fmt):
        print(f"\n## {title} ({len(items)})")
        for r in items:
            print("  " + fmt(r))

    show("TAKEOVER — grab vocabulary AND the entry's own words are gone", takeover,
         lambda r: f"{r['id']}\n    {r['url']}\n    hits: {', '.join(r['takeover_hits'])}")
    show("SPAM ON A LIVE PAGE — grab vocabulary but the article is still there", spammed,
         lambda r: f"overlap {r['overlap']:.2f}  {r['id']}\n    hits: {', '.join(r['takeover_hits'])}")
    show(f"DRIFT — {int(args.drift_below*100)}% or less of the title's words survive", drift,
         lambda r: f"{r['overlap']:.2f}  {r['id']}\n         {r['url']}")
    show("TOO LITTLE TEXT — fetch returned almost nothing, cannot judge", thin,
         lambda r: f"{r['chars']:>5}  {r['id']}")
    show("NOT READABLE — a PDF, or a page whose text is built by JavaScript",
         unreadable, lambda r: f"{r['error']:<32} {r['id']}")
    show("BLOCKED — host answered and refused automation; says nothing about the page",
         blocked, lambda r: f"{r['error']:<14} {r['id']}")
    show("FETCH FAILED", errors, lambda r: f"{r['error']:<24} {r['id']}")

    print(f"\n---\n{len(rows) - flagged}/{len(rows)} entries look like themselves.")
    print(f"takeover {len(takeover)} · spammed {len(spammed)} · drift {len(drift)} "
          f"· thin {len(thin)} · unreadable {len(unreadable)} · blocked {len(blocked)} "
          f"· failed {len(errors)}")
    print(f"({len(homepages)} homepage-shaped entries were fetched but not drift-checked)")

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print(f"wrote {args.json}")
    return 1 if takeover else 0


if __name__ == "__main__":
    sys.exit(main())
