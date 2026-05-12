#!/usr/bin/env python3
"""PR auto-review bot.

Runs in GitHub Actions on pull_request events that touch data/**.
Grades each newly-added or modified YAML entry against RUBRIC.md, posts a
single structured comment on the PR, and applies advisory labels.

LLM inference goes through GitHub Models (free for public repos via
`permissions: models: read`). When inference fails or quota is exhausted,
falls back to deterministic format/reachability checks only.

Environment:
  GITHUB_TOKEN         provided by Actions; used for both Models + REST
  GITHUB_REPOSITORY    owner/repo
  PR_NUMBER            target pull request
  GITHUB_EVENT_PATH    JSON event payload (for diff context)
  REVIEW_MODE          "post" (default) | "dryrun" (artifact only, no PR comment)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# SCRIPT_ROOT is where this trusted script lives. TEMPLATES + generate.py are
# loaded from here, so pr-review-backlog.yml can stash trusted scripts in
# /tmp/awsec-trusted/ and run them while the working tree holds an untrusted
# PR checkout. WORKDIR is the actual git tree where data/ lives.
SCRIPT_ROOT = Path(__file__).resolve().parent.parent.parent
WORKDIR = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
TEMPLATES_DIR = SCRIPT_ROOT / "scripts" / "ci" / "templates"
DATA_DIR = WORKDIR / "data"
INDEX_FILE = DATA_DIR / "index.json"

sys.path.insert(0, str(SCRIPT_ROOT / "scripts"))
from generate import parse_yaml  # noqa: E402

GH_API = "https://api.github.com"
GH_MODELS = "https://models.github.ai/inference"
DEFAULT_MODEL = os.environ.get("REVIEW_MODEL", "openai/gpt-4.1-mini")
EMBED_MODEL = os.environ.get("REVIEW_EMBED_MODEL", "cohere/Cohere-embed-v3-multilingual")

TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
PR_NUMBER = os.environ.get("PR_NUMBER", "")
REVIEW_MODE = os.environ.get("REVIEW_MODE", "post")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http(url: str, *, method: str = "GET", headers: dict | None = None,
         data: dict | None = None, timeout: int = 30) -> tuple[int, dict | str]:
    body = None
    h = dict(headers or {})
    if data is not None:
        body = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct:
                return resp.status, json.loads(raw or "{}")
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def gh_api(path: str, *, method: str = "GET", data: dict | None = None) -> tuple[int, dict | str]:
    return http(f"{GH_API}/{path.lstrip('/')}",
                method=method,
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "awesome-web-security-bot",
                },
                data=data)


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

def changed_yaml_files() -> list[Path]:
    """Files changed in this PR under data/entries/*.yml."""
    base = os.environ.get("GITHUB_BASE_REF") or "master"
    subprocess.run(["git", "fetch", "origin", base], cwd=WORKDIR,
                   capture_output=True, check=False)
    out = subprocess.run(
        ["git", "diff", "--name-only", f"origin/{base}...HEAD", "--", "data/entries/"],
        cwd=WORKDIR, capture_output=True, text=True, check=True,
    ).stdout
    return [WORKDIR / line for line in out.splitlines() if line.endswith(".yml")]


def added_entries_in_pr() -> list[dict]:
    """Return list of entry dicts added or modified in this PR."""
    base = os.environ.get("GITHUB_BASE_REF") or "master"
    results: list[dict] = []
    for fp in changed_yaml_files():
        if not fp.exists():
            continue
        cur = parse_yaml(fp.read_text(encoding="utf-8")).get("entries", [])
        cur_by_id = {e.get("id"): e for e in cur if e.get("id")}
        try:
            base_text = subprocess.run(
                ["git", "show", f"origin/{base}:{fp.relative_to(WORKDIR)}"],
                cwd=WORKDIR, capture_output=True, text=True, check=True,
            ).stdout
            base_entries = parse_yaml(base_text).get("entries", [])
            base_ids = {e.get("id") for e in base_entries if e.get("id")}
        except subprocess.CalledProcessError:
            base_ids = set()
        for eid, entry in cur_by_id.items():
            if eid not in base_ids:
                results.append(entry)
    return results


# ---------------------------------------------------------------------------
# Deterministic checks
# ---------------------------------------------------------------------------

def check_reachability(url: str) -> tuple[int, str]:
    """Return (score, reason)."""
    if not url:
        return 0, "URL missing"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return 0, f"invalid scheme `{parsed.scheme}`"
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Mozilla/5.0 awesome-web-security-bot"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            final = resp.url
    except urllib.error.HTTPError as exc:
        # try GET in case HEAD blocked
        if exc.code in (403, 405):
            try:
                with urllib.request.urlopen(urllib.request.Request(
                        url, headers={"User-Agent": "Mozilla/5.0 awesome-web-security-bot"}
                ), timeout=15) as resp:
                    status = resp.status
                    final = resp.url
            except Exception as e2:
                return 0, f"HTTP {exc.code} then {type(e2).__name__}"
        else:
            return 0, f"HTTP {exc.code}"
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"
    if status >= 400:
        return 0, f"HTTP {status}"
    redirected = (urlparse(final).geturl().rstrip("/") != url.rstrip("/"))
    same_host = (urlparse(final).netloc == parsed.netloc)
    if parsed.scheme == "https" and not redirected:
        return 3, f"{status} HTTPS, no redirects"
    if parsed.scheme == "https" and same_host:
        return 2, f"{status} HTTPS, one same-host redirect"
    if parsed.scheme == "http":
        return 1, f"{status} HTTP (HTTPS preferred)"
    return 1, f"{status} multi-hop redirect"


def check_format(entry: dict, categories: set[str]) -> tuple[int, str]:
    required = ("id", "url", "title", "category", "type", "languages",
                "difficulty", "date_added", "status")
    missing = [k for k in required if entry.get(k) in (None, "")]
    if missing:
        return 0, f"missing fields: {', '.join(missing)}"
    if entry.get("category") not in categories:
        return 0, f"unknown category `{entry.get('category')}`"
    enum_ok = (
        entry.get("type") in {"article", "tool", "cheatsheet", "video", "book", "community", "payload-list"}
        and entry.get("difficulty") in {"intro", "intermediate", "advanced"}
        and entry.get("status") in {"active", "dead", "archived-only", "quarantined"}
    )
    has_optional = bool(entry.get("author")) and bool(entry.get("languages"))
    if enum_ok and has_optional:
        return 3, "all fields valid"
    if enum_ok:
        return 2, "required fields valid"
    return 1, "one or more enum values out of range"


# ---------------------------------------------------------------------------
# LLM grading
# ---------------------------------------------------------------------------

LLM_SYSTEM_TEMPLATE = """You are reviewing one entry proposed for awesome-web-security, a curated
Markdown list of web security learning resources. Grade strictly against the
five-dimension rubric. Never auto-approve or auto-reject; your output is
advisory only.

OUTPUT LANGUAGE: {target_lang_name} ({target_lang_code}).
All `*_reason` field values MUST be written in {target_lang_name}. Do NOT use
any other natural language. The contributor's language was classified
deterministically before this prompt; do not second-guess it.

Output a single JSON object matching this schema exactly:
{{
  "reachability": int 0-3, "reachability_reason": "...",
  "format": int 0-3, "format_reason": "...",
  "depth": int 0-3, "depth_reason": "...",
  "fit": int 0-3, "fit_reason": "...",
  "dedup_risk": int 0-3, "dedup_reason": "...",
  "similar_entries": [{{"id": "...", "cosine": 0.0}}],
  "language_routing_suggestion": "en|zh|jp|universal",
  "blocking_issues": []
}}

`language_routing_suggestion` is about which README(s) the entry belongs in
based on the resource's audience; it is NOT the output-language directive
above.

Dimension names (Reachability/Format/Depth/Fit/Dedup) are rubric keys; do
not translate them. Output JSON only, no prose around it.
"""

_LANG_NAME = {"en": "English", "zh": "Simplified Chinese", "jp": "Japanese"}


def call_models(model: str, payload: dict) -> dict | None:
    status, body = http(
        f"{GH_MODELS}/chat/completions" if "embed" not in model.lower() else f"{GH_MODELS}/embeddings",
        method="POST",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json",
        },
        data=payload,
        timeout=60,
    )
    if status != 200 or not isinstance(body, dict):
        sys.stderr.write(f"[models] status={status} body={str(body)[:200]}\n")
        return None
    return body


def llm_grade(entry: dict, neighbors: list[dict], target_lang: str) -> dict | None:
    user_prompt = json.dumps({
        "entry": {
            "id": entry.get("id"),
            "url": entry.get("url"),
            "title": entry.get("title"),
            "author": entry.get("author"),
            "category": entry.get("category"),
            "type": entry.get("type"),
            "difficulty": entry.get("difficulty"),
            "languages": entry.get("languages"),
        },
        "nearest_existing_entries_in_same_category": neighbors[:5],
    }, ensure_ascii=False)

    system_prompt = LLM_SYSTEM_TEMPLATE.format(
        target_lang_code=target_lang,
        target_lang_name=_LANG_NAME.get(target_lang, "English"),
    )

    body = call_models(DEFAULT_MODEL, {
        "model": DEFAULT_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    })
    if not body:
        return None
    try:
        content = body["choices"][0]["message"]["content"]
        # strip code fences if present
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.MULTILINE)
        return json.loads(content)
    except Exception as exc:
        sys.stderr.write(f"[models] parse failure: {exc}\n")
        return None


# ---------------------------------------------------------------------------
# Comment assembly
# ---------------------------------------------------------------------------

# CJK Unified Ideographs + Hiragana + Katakana + Hangul + CJK compat blocks.
# Used to detect when the LLM emitted a non-English reason in an English-
# template comment (or vice versa). Codepoint ranges are spelled out as
# \uXXXX escapes so the regex is readable in a diff (the inline-character
# form, e.g. `一-鿿`, works identically but reads as gibberish).
_CJK_RE = re.compile(
    "["
    "\u3040-\u30FF"   # Hiragana + Katakana
    "\u3400-\u4DBF"   # CJK Unified Ideographs Extension A
    "\u4E00-\u9FFF"   # CJK Unified Ideographs (main block)
    "\uAC00-\uD7AF"   # Hangul Syllables
    "\uF900-\uFAFF"   # CJK Compatibility Ideographs
    "]"
)


def has_cjk(text) -> bool:
    return bool(_CJK_RE.search(str(text or "")))


# Sub-ranges of _CJK_RE, used to distinguish Japanese (Kana present) from
# Chinese (Han only).
_HAN_RE = re.compile("[㐀-䶿一-鿿豈-﫿]")
_KANA_RE = re.compile("[぀-ヿ]")


def detect_lang(text) -> str:
    """Best-effort language classification on the contributor's PR body.

    Deterministic: no LLM, no library. Returns "en", "zh", or "jp".
    Korean Hangul and any other script falls back to English.
    """
    s = str(text or "")
    if not s:
        return "en"
    if _KANA_RE.search(s):
        return "jp"
    if _HAN_RE.search(s):
        return "zh"
    return "en"


def pick_template_lang(target_lang: str | None) -> str:
    """Validate and clamp the detected language to a template we ship."""
    return target_lang if target_lang in ("en", "zh", "jp") else "en"


def harmonize_reason(text: str, template_lang: str) -> str:
    """If the LLM emitted a reason in the wrong language for the picked
    template, replace it with a safe fallback so the comment doesn't read
    half-English half-CJK.
    """
    if template_lang == "en" and has_cjk(text):
        return "(LLM emitted non-English reason; see score above)"
    return text


def clamp_dim(value) -> int:
    """Coerce an LLM-supplied score to the 0..3 range."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(3, n))


def sanitize_reason(text) -> str:
    """Neutralize markdown / table-cell injection from LLM-laundered PR content.

    Strips newlines, escapes characters that could close a code span, escape
    a table cell, or smuggle a link. Caps at 120 chars. The output is safe
    to drop into a `| {reason} |` table cell.
    """
    if text is None:
        return ""
    s = str(text)
    # collapse whitespace (incl. newlines)
    s = re.sub(r"\s+", " ", s).strip()
    # neutralize markdown control chars
    s = s.replace("\\", "\\\\")
    for ch in ("`", "|", "[", "]", "(", ")", "<", ">"):
        s = s.replace(ch, "\\" + ch)
    if len(s) > 120:
        s = s[:117] + "..."
    return s


def label_for(score: int, dims: dict) -> str:
    if dims.get("reachability", 0) == 0:
        return "auto/link-broken"
    if dims.get("dedup_risk", 0) == 0:
        return "auto/dedup-candidate"
    if score >= 11:
        return "auto/format-ok"
    if score >= 7:
        return "auto/needs-format-fix"
    return "auto/needs-major-revision"


def pick_template(template_lang: str) -> str:
    path = TEMPLATES_DIR / f"comment.{template_lang}.md"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return (TEMPLATES_DIR / "comment.en.md").read_text(encoding="utf-8")


def render_similar(similar: list[dict]) -> str:
    if not similar:
        return ""
    rows = ["**Similar entries**:"]
    for s in similar[:3]:
        sid = re.sub(r"[^a-zA-Z0-9\-_]", "", str(s.get("id", "?")))[:80] or "?"
        try:
            cos = float(s.get("cosine", 0))
        except (TypeError, ValueError):
            cos = 0.0
        cos = max(0.0, min(1.0, cos))
        rows.append(f"- `{sid}` (cosine {cos:.2f})")
    return "\n".join(rows)


SAFE_LANG_ROUTING = {"en", "zh", "jp", "tr", "universal"}


def render_comment(scored: dict, target_lang: str, deterministic_fallback: bool) -> tuple[str, str]:
    # Clamp every dim into 0..3. LLM-supplied scores are not trusted; prompt
    # injection from the PR body could otherwise emit `"format": 999` and
    # flip the bot into auto/format-ok on a bad entry.
    dims = {
        "reachability": clamp_dim(scored.get("reachability")),
        "format": clamp_dim(scored.get("format")),
        "depth": clamp_dim(scored.get("depth")),
        "fit": clamp_dim(scored.get("fit")),
        "dedup_risk": clamp_dim(scored.get("dedup_risk")),
    }
    total = sum(dims.values())
    label = label_for(total, dims)

    routing = scored.get("language_routing_suggestion", "en")
    if routing not in SAFE_LANG_ROUTING:
        routing = "en"

    template_lang = pick_template_lang(target_lang)
    tmpl = pick_template(template_lang)

    # Defensive: if the LLM ignored its instructions and emitted CJK in
    # English-template territory (or some future inverse), swap the reason
    # for a safe placeholder so the comment doesn't read half-mixed.
    def cell(key: str) -> str:
        raw = scored.get(key)
        return sanitize_reason(harmonize_reason(raw, template_lang))

    body = tmpl.format(
        score=total,
        label=label,
        reachability=dims["reachability"],
        reachability_reason=cell("reachability_reason"),
        format=dims["format"],
        format_reason=cell("format_reason"),
        depth=dims["depth"],
        depth_reason=cell("depth_reason"),
        fit=dims["fit"],
        fit_reason=cell("fit_reason"),
        dedup_risk=dims["dedup_risk"],
        dedup_reason=cell("dedup_reason"),
        similar_block=render_similar(scored.get("similar_entries") or []),
        language_routing_suggestion=routing,
    )
    if deterministic_fallback:
        body += "\n\n_⚠️ LLM grading unavailable; only deterministic checks ran._"
    return body, label


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def pr_body() -> str:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        return (event.get("pull_request") or {}).get("body") or ""
    except Exception:
        return ""


def neighbors_for(entry: dict) -> list[dict]:
    """Cheap heuristic: nearest neighbors from index.json filtered by category.

    Excludes the entry itself (matched by id). The PR branch's index.json
    has already been regenerated to include the new entry, so without this
    guard `neighbors_for` returns the entry as its own cosine-1.0 neighbor
    and the bot flags `dedup_risk: 0` (near-duplicate) on every clean PR.
    """
    if not INDEX_FILE.exists():
        return []
    idx = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    own_id = entry.get("id")
    same_cat = [e for e in idx.get("entries", [])
                if e.get("category") == entry.get("category")
                and e.get("id") != own_id]
    title = (entry.get("title") or "").lower()
    title_terms = set(re.findall(r"[a-z0-9]+", title))
    scored: list[tuple[float, dict]] = []
    for e in same_cat:
        t = set(re.findall(r"[a-z0-9]+", (e.get("title") or "").lower()))
        if not t or not title_terms:
            continue
        cosine = len(t & title_terms) / max(1, (len(t) ** 0.5 * len(title_terms) ** 0.5))
        scored.append((cosine, e))
    scored.sort(key=lambda x: -x[0])
    return [{"id": e.get("id"), "cosine": round(c, 2)} for c, e in scored[:5]]


def post_comment(body: str) -> None:
    status, resp = gh_api(
        f"repos/{REPO}/issues/{PR_NUMBER}/comments",
        method="POST",
        data={"body": body},
    )
    if status >= 300:
        sys.stderr.write(f"comment post failed: {status} {resp}\n")


def apply_label(label: str) -> None:
    status, resp = gh_api(
        f"repos/{REPO}/issues/{PR_NUMBER}/labels",
        method="POST",
        data={"labels": [label]},
    )
    if status >= 300:
        sys.stderr.write(f"label apply failed: {status} {resp}\n")


def categories_set() -> set[str]:
    try:
        sections = parse_yaml((DATA_DIR / "categories.yml").read_text(encoding="utf-8")).get("sections", [])
        return {s["key"] for s in sections}
    except FileNotFoundError:
        return set()


def main() -> int:
    if not TOKEN or not REPO or not PR_NUMBER:
        print("missing GITHUB_TOKEN / GITHUB_REPOSITORY / PR_NUMBER", file=sys.stderr)
        return 1

    cats = categories_set()
    entries = added_entries_in_pr()
    if not entries:
        print("no entry changes in data/entries; skipping LLM grading")
        return 0

    pr = pr_body()
    # Classify contributor language ONCE per run from the PR body. The LLM
    # gets this as a directive (input), not as something to detect (output).
    target_lang = detect_lang(pr)
    print(f"detected contributor language: {target_lang}")

    summaries: list[tuple[str, str]] = []   # (comment, label)
    for entry in entries:
        # Deterministic baseline
        reach_score, reach_reason = check_reachability(entry.get("url", ""))
        fmt_score, fmt_reason = check_format(entry, cats)
        neighbors = neighbors_for(entry)
        scored = llm_grade(entry, neighbors, target_lang)
        fallback = False
        if scored is None:
            fallback = True
            scored = {
                "reachability": reach_score, "reachability_reason": reach_reason,
                "format": fmt_score, "format_reason": fmt_reason,
                "depth": 1, "depth_reason": "skipped (LLM unavailable)",
                "fit": 1, "fit_reason": "skipped (LLM unavailable)",
                "dedup_risk": 2, "dedup_reason": f"top neighbor cosine ~{neighbors[0]['cosine'] if neighbors else 0}",
                "similar_entries": neighbors,
                "language_routing_suggestion": (entry.get("languages") or ["en"])[0],
            }
        else:
            # always merge in deterministic reach + format scores (LLM tends to over-rate reachability)
            scored["reachability"] = reach_score
            scored["reachability_reason"] = reach_reason
            scored["format"] = fmt_score
            scored["format_reason"] = fmt_reason

        body, label = render_comment(scored, target_lang, fallback)
        body = f"#### Entry: `{entry.get('id')}`\n\n" + body
        summaries.append((body, label))

    final = "\n\n---\n\n".join(b for b, _ in summaries)

    if REVIEW_MODE == "dryrun":
        out = Path(os.environ.get("GITHUB_OUTPUT_DIR", "/tmp")) / f"review-{PR_NUMBER}.md"
        out.write_text(final, encoding="utf-8")
        print(f"dryrun: wrote {out}")
        return 0

    post_comment(final)
    labels_to_apply = {label for _, label in summaries}
    for lab in labels_to_apply:
        apply_label(lab)
    print(f"posted review with {len(summaries)} entry block(s); labels={labels_to_apply}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
