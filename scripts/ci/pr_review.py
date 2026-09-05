#!/usr/bin/env python3
"""PR auto-review bot.

Runs in GitHub Actions on pull_request events that touch data/**.
Grades each newly-added or modified YAML entry against RUBRIC.md, posts a
single structured comment on the PR, and applies advisory labels.

LLM inference went through GitHub Models, which GitHub retired entirely on
2026-07-30: `models.github.ai` is gone and `permissions: models: read` no
longer grants anything. Every call now fails and the bot runs on its
deterministic path (reachability + format + local dedup), which is why the
Depth and Fit dimensions report "skipped". Picking a replacement backend is
tracked separately; the call sites below are left intact so that migration is
a one-function change.

Environment:
  GITHUB_TOKEN         provided by Actions; used for both Models + REST
  GITHUB_REPOSITORY    owner/repo
  PR_NUMBER            target pull request
  GITHUB_EVENT_PATH    JSON event payload (for diff context)
  REVIEW_MODE          "post" (default) | "dryrun" (artifact only, no PR comment)
  PR_HEAD_SHA          head commit of the PR; binds a dryrun artifact to its run
  GITHUB_OUTPUT_DIR    where dryrun writes review-<PR>.{md,json}
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
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
    """Return list of entry dicts newly added in this PR (by id not present in base)."""
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


# Added markdown list item in a generated README, e.g.
#   +- [Title](https://example.com) - One-line description.
LEGACY_LINK_RE = re.compile(r"^\+\s*-\s*\[([^\]]+)\]\(([^)\s]+)")

GENERATED_READMES = ("README.md", "README-zh.md", "README-jp.md")


def legacy_readme_links() -> list[tuple[str, str]]:
    """(title, url) pairs added straight into a generated README by this PR.

    The READMEs are build output, so an entry that only appears there is lost
    on the next `generate.py` run. Grading these keeps README-shape PRs from
    getting silence, which is what they got before: pr-review.yml did not even
    trigger on README paths.
    """
    base = os.environ.get("GITHUB_BASE_REF") or "master"
    subprocess.run(["git", "fetch", "origin", base], cwd=WORKDIR,
                   capture_output=True, check=False)
    out = subprocess.run(
        ["git", "diff", f"origin/{base}...HEAD", "--", *GENERATED_READMES],
        cwd=WORKDIR, capture_output=True, text=True, check=False,
    ).stdout
    seen: set[str] = set()
    found: list[tuple[str, str]] = []
    for line in out.splitlines():
        m = LEGACY_LINK_RE.match(line)
        if not m:
            continue
        title, url = m.group(1).strip(), m.group(2).strip()
        if url in seen:
            continue
        seen.add(url)
        found.append((title, url))
    return found


# ---------------------------------------------------------------------------
# Deterministic checks
# ---------------------------------------------------------------------------

def _host_is_non_public(host: str) -> bool:
    """True if `host` resolves to any non-public address.

    The entry URL is attacker-controlled (it comes straight from the PR's
    YAML), and check_reachability fetches it from inside CI. Without this
    guard the bot is an SSRF primitive: a PR could point `url` at the cloud
    metadata endpoint (169.254.169.254) or an internal service. We resolve
    every address the host maps to and reject loopback / private / link-local
    / reserved / multicast / unspecified ranges.

    Note: this is a hostname-level check and does not fully close DNS
    rebinding (a host that resolves public here but private at connect time).
    That residual is acceptable for a link-checker whose only output is a
    0-3 score and a short status string — no response body is ever returned.
    """
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable: let the real request fail normally rather than
        # mislabel it "non-public".
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast
                or addr.is_unspecified):
            return True
    return False


class _BlockInternalRedirect(urllib.request.HTTPRedirectHandler):
    """Re-validate the target host on every redirect hop. urllib follows
    redirects automatically, so a public URL that 30x-es to an internal one
    would otherwise sail past the pre-request check."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _host_is_non_public(urlparse(newurl).hostname or ""):
            raise urllib.error.URLError("redirect to non-public host blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(_BlockInternalRedirect())


def check_reachability(url: str) -> tuple[int, str]:
    """Return (score, reason)."""
    if not url:
        return 0, "URL missing"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return 0, f"invalid scheme `{parsed.scheme}`"
    if _host_is_non_public(parsed.hostname or ""):
        return 0, "host resolves to a non-public address"
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Mozilla/5.0 awesome-web-security-bot"})
        with _SAFE_OPENER.open(req, timeout=15) as resp:
            status = resp.status
            final = resp.url
    except urllib.error.HTTPError as exc:
        # try GET in case HEAD blocked
        if exc.code in (403, 405):
            try:
                with _SAFE_OPENER.open(urllib.request.Request(
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


def code_span(text) -> str:
    """Wrap untrusted text in a code span it cannot escape."""
    s = re.sub(r"\s+", " ", str(text or "")).replace("`", "").strip()
    if len(s) > 200:
        s = s[:197] + "..."
    return f"`{s}`"


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


# Dimensions the deterministic path can actually measure. Depth, Fit and Dedup
# all needed the LLM (Dedup needed the embedding endpoint), so with GitHub
# Models gone they are not scored at all rather than reported as a 1/3 that
# looks like a judgement.
MEASURED_DIMS = ("reachability", "format")
DEGRADED_MAX = 3 * len(MEASURED_DIMS)
FULL_MAX = 15


def label_for(score: int, dims: dict, *, degraded: bool = False) -> str:
    if dims.get("reachability", 0) == 0:
        return "auto/link-broken"
    if dims.get("dedup_risk", 0) == 0:
        return "auto/dedup-candidate"
    if degraded:
        # Only Reachability and Format were measured, so a merit label would be
        # a guess dressed as a verdict. Report the defect if there is one and
        # otherwise say the thing that IS true: the format checks passed.
        # Without this, the 15-point thresholds label a flawless entry
        # `auto/needs-format-fix`, because the unscored dimensions cap the
        # total at 6 and nothing can reach 11. That happened to #231.
        return "auto/needs-format-fix" if dims.get("format", 0) < 3 else "auto/format-ok"
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


_DEGRADED_NOTE = {
    "en": ("\n_⚠️ Depth, Fit and Dedup were not scored: the reviewer's model backend "
           "(GitHub Models) was retired, so only the deterministic checks ran. The score "
           "above covers those two dimensions alone and is **not** a judgement on the "
           "resource — the maintainer weighs Depth and Fit by hand._"),
    "zh": ("\n_⚠️ Depth、Fit、Dedup 未評分：審查機器人的模型後端（GitHub Models）已終止服務，"
           "因此只跑了確定性檢查。上面的分數僅涵蓋那兩個維度，**不代表**對資源本身的判斷"
           "——Depth 與 Fit 由維護者人工衡量。_"),
    "jp": ("\n_⚠️ Depth・Fit・Dedup は未採点です：レビューアのモデルバックエンド（GitHub Models）"
           "が提供終了となったため、決定的チェックのみが実行されました。上のスコアはその 2 項目"
           "のみを対象としており、リソース自体への**評価ではありません**——Depth と Fit は"
           "メンテナーが手作業で判断します。_"),
}


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
    if deterministic_fallback:
        # Score only what was measured. Summing the placeholder 1/3s into a
        # /15 total invents a number that reads as a verdict on the entry.
        total = sum(dims[k] for k in MEASURED_DIMS)
        max_score = DEGRADED_MAX
    else:
        total = sum(dims.values())
        max_score = FULL_MAX
    label = label_for(total, dims, degraded=deterministic_fallback)

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

    def score_cell(key: str) -> str:
        """`2/3`, or an em dash for a dimension this run could not judge."""
        if deterministic_fallback and key not in MEASURED_DIMS:
            return "—"
        return f"{dims[key]}/3"

    body = tmpl.format(
        score=total,
        max_score=max_score,
        label=label,
        reachability=score_cell("reachability"),
        reachability_reason=cell("reachability_reason"),
        format=score_cell("format"),
        format_reason=cell("format_reason"),
        depth=score_cell("depth"),
        depth_reason=cell("depth_reason"),
        fit=score_cell("fit"),
        fit_reason=cell("fit_reason"),
        dedup_risk=score_cell("dedup_risk"),
        dedup_reason=cell("dedup_reason"),
        similar_block=render_similar(scored.get("similar_entries") or []),
        language_routing_suggestion=routing,
        mode_note=(_DEGRADED_NOTE.get(template_lang, _DEGRADED_NOTE["en"])
                   if deterministic_fallback else ""),
    )
    return re.sub(r"\n{3,}", "\n\n", body).rstrip() + "\n", label


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

_LEGACY_NOTICE = {
    "en": (
        "#### Direct README edit\n\n"
        "`README.md`, `README-zh.md` and `README-jp.md` are **generated** from "
        "`data/entries/*.yml` by `scripts/generate.py`. A line added straight to a "
        "README is overwritten the next time the generator runs, so this PR cannot "
        "land as-is. Move the entry into the YAML file for its section, run "
        "`python3 scripts/generate.py`, and commit the regenerated output — "
        "CONTRIBUTING.md has the schema.\n\n"
        "Reachability of the link(s) added here, checked just now:\n\n{links}"
    ),
    "zh": (
        "#### 直接修改了 README\n\n"
        "`README.md`、`README-zh.md` 和 `README-jp.md` 是由 `scripts/generate.py` "
        "從 `data/entries/*.yml` **產生**的。直接加在 README 的那一行會在下次重新產生時被覆蓋，"
        "所以這個 PR 無法照現在的形式合併。請把條目加進對應章節的 YAML 檔，執行 "
        "`python3 scripts/generate.py`，再把重新產生的檔案一起提交——schema 在 CONTRIBUTING.md。\n\n"
        "剛剛檢查了這裡新增連結的可達性：\n\n{links}"
    ),
    "jp": (
        "#### README の直接編集\n\n"
        "`README.md`、`README-zh.md`、`README-jp.md` は `scripts/generate.py` が "
        "`data/entries/*.yml` から**生成**しています。README に直接追加した行は次回の生成時に"
        "上書きされるため、この PR はこのままではマージできません。該当セクションの YAML "
        "ファイルにエントリを追加し、`python3 scripts/generate.py` を実行して、生成物も"
        "コミットしてください。スキーマは CONTRIBUTING.md にあります。\n\n"
        "追加されたリンクの到達性をいま確認しました：\n\n{links}"
    ),
}


def render_legacy_notice(links: list[tuple[str, str]], target_lang: str) -> tuple[str, str]:
    """Comment block for a PR that only touched the generated READMEs."""
    rows = []
    worst = 3
    for title, url in links[:10]:
        score, reason = check_reachability(url)
        worst = min(worst, score)
        mark = "✅" if score >= 2 else ("⚠️" if score == 1 else "❌")
        # Both fields come from the PR diff. Code spans keep them from forming
        # links, closing table cells, or pinging accounts with a bare @handle.
        rows.append(f"- {mark} {code_span(url)} {code_span(title)} — {sanitize_reason(reason)}")
    if len(links) > 10:
        rows.append(f"- …and {len(links) - 10} more, not checked")

    template = _LEGACY_NOTICE.get(pick_template_lang(target_lang), _LEGACY_NOTICE["en"])
    body = template.format(links="\n".join(rows))
    return body, ("auto/link-broken" if worst == 0 else "auto/needs-format-fix")


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
    # A PR that only touched the generated READMEs still gets graded — that is
    # the legacy submission shape, and silence on it is what let README-only
    # PRs sit unreviewed.
    legacy = [] if entries else legacy_readme_links()
    if not entries and not legacy:
        print("nothing to review: no new data/entries and no README list items added")
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
                # neighbors_for is a local title-token overlap, not the multilingual
                # embedding RUBRIC.md's bands were calibrated against, so the number
                # is worth showing but not worth scoring against those thresholds.
                "dedup_risk": 2,
                "dedup_reason": (f"not scored; nearest title-overlap neighbour "
                                 f"~{neighbors[0]['cosine'] if neighbors else 0} "
                                 f"(heuristic, not the embedding metric)"),
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

    if legacy:
        summaries.append(render_legacy_notice(legacy, target_lang))
        print(f"README-only PR: graded {len(legacy)} added link(s)")

    final = "\n\n---\n\n".join(b for b, _ in summaries)
    labels = sorted({label for _, label in summaries})

    if REVIEW_MODE == "dryrun":
        outdir = Path(os.environ.get("GITHUB_OUTPUT_DIR", "/tmp"))
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / f"review-{PR_NUMBER}.md").write_text(final, encoding="utf-8")
        # Structured payload for pr-review-publish.yml. head_sha is what binds
        # this artifact to the run that produced it; the publisher refuses a
        # payload whose SHA does not match the PR it claims to be about.
        (outdir / f"review-{PR_NUMBER}.json").write_text(json.dumps({
            "pr_number": PR_NUMBER,
            "head_sha": os.environ.get("PR_HEAD_SHA", ""),
            "labels": labels,
            "body": final,
        }, ensure_ascii=False), encoding="utf-8")
        print(f"dryrun: wrote review-{PR_NUMBER}.json ({len(summaries)} block(s), labels={labels})")
        return 0

    post_comment(final)
    for lab in labels:
        apply_label(lab)
    print(f"posted review with {len(summaries)} entry block(s); labels={set(labels)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
