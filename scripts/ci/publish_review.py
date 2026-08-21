#!/usr/bin/env python3
"""Post the review that pr_review.py graded in dryrun mode.

Runs from pr-review-publish.yml on a `workflow_run` trigger, which is the only
context where a fork PR can be commented on without giving a write token to a
workflow that has checked out the contributor's code. This script is therefore
the privileged half of the pair, and it treats its input accordingly:

  * The artifact is untrusted. It was produced by a job holding no secrets, but
    it is still a file from a run triggered by an outside contributor.
  * `head_sha` binds the payload to the run that produced it. A payload naming
    a PR whose current head differs is stale or forged; either way it is dropped.
  * Labels are filtered against an allowlist. Body length is capped.
  * The PR is never checked out here, and nothing from it is executed.

Environment:
  GITHUB_TOKEN           write-scoped token from the base repo
  GITHUB_REPOSITORY      owner/repo
  REVIEW_ARTIFACT_DIR    directory holding review-<PR>.json
  WORKFLOW_RUN_ID        id of the producing workflow_run; its head SHA is
                         resolved from the API rather than passed in
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

GH_API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
ARTIFACT_DIR = Path(os.environ.get("REVIEW_ARTIFACT_DIR", "/tmp/review"))
RUN_ID = os.environ.get("WORKFLOW_RUN_ID", "")

# Every label the bot is allowed to apply. RUBRIC.md documents the first five;
# auto/review-failed is the fallback path's own marker.
ALLOWED_LABELS = {
    "auto/format-ok",
    "auto/needs-format-fix",
    "auto/needs-major-revision",
    "auto/link-broken",
    "auto/dedup-candidate",
    "auto/review-failed",
}

# GitHub rejects comment bodies over 65536 characters.
MAX_BODY = 60000

# Identifies the bot's own comment so repeated runs update it instead of
# stacking a new one on every push.
MARKER = "<!-- awsec-auto-review -->"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def gh_api(path: str, *, method: str = "GET", data: dict | None = None) -> tuple[int, object]:
    req = urllib.request.Request(
        f"{GH_API}/{path.lstrip('/')}",
        method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "awesome-web-security-bot",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:400]
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def load_payload() -> dict | None:
    """Read the single review payload, or None if there is nothing to publish."""
    if not ARTIFACT_DIR.is_dir():
        print("no artifact directory; nothing to publish")
        return None
    candidates = sorted(ARTIFACT_DIR.glob("review-*.json"))
    if not candidates:
        print("no review payload in artifact; nothing to publish")
        return None
    if len(candidates) > 1:
        # The producing job writes exactly one. More than one means something
        # planted files in the output directory.
        print(f"refusing to publish: {len(candidates)} payloads in artifact", file=sys.stderr)
        return None
    try:
        payload = json.loads(candidates[0].read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"refusing to publish: unreadable payload ({exc})", file=sys.stderr)
        return None
    return payload if isinstance(payload, dict) else None


def producing_run_head_sha() -> str:
    """Head SHA of the workflow_run that produced the artifact, from the API.

    Deliberately not taken from the event payload: resolving it here keeps
    every fact this script checks on one authenticated path, and keeps the
    calling workflow free of a `workflow_run.head_sha` reference — the token
    that static analysis reasonably reads as a pwn-request checkout.
    """
    if not RUN_ID.isdigit():
        print(f"refusing: malformed run id {RUN_ID!r}", file=sys.stderr)
        return ""
    status, run = gh_api(f"repos/{REPO}/actions/runs/{RUN_ID}")
    if status != 200 or not isinstance(run, dict):
        print(f"refusing: cannot read run {RUN_ID} ({status})", file=sys.stderr)
        return ""
    return str(run.get("head_sha") or "")


def validate(payload: dict) -> tuple[str, str, list[str]] | None:
    """Return (pr_number, body, labels) if the payload is safe to act on."""
    pr_number = str(payload.get("pr_number", ""))
    head_sha = str(payload.get("head_sha", ""))
    body = payload.get("body")
    labels = payload.get("labels") or []

    if not pr_number.isdigit():
        print(f"refusing: malformed pr_number {pr_number!r}", file=sys.stderr)
        return None
    if not SHA_RE.match(head_sha):
        print(f"refusing: malformed head_sha {head_sha!r}", file=sys.stderr)
        return None
    if not isinstance(body, str) or not body.strip():
        print("refusing: empty body", file=sys.stderr)
        return None
    if not isinstance(labels, list) or not all(isinstance(x, str) for x in labels):
        print("refusing: malformed labels", file=sys.stderr)
        return None

    # The payload must describe the run that carried it...
    run_head = producing_run_head_sha()
    if not run_head:
        return None
    if head_sha != run_head:
        print(f"refusing: payload head {head_sha[:12]} != run head {run_head[:12]}",
              file=sys.stderr)
        return None

    # ...and that run must be the current head of the PR it names. This is what
    # stops a payload from claiming to be about a different pull request.
    status, pr = gh_api(f"repos/{REPO}/pulls/{pr_number}")
    if status != 200 or not isinstance(pr, dict):
        print(f"refusing: cannot read PR #{pr_number} ({status})", file=sys.stderr)
        return None
    actual = (pr.get("head") or {}).get("sha", "")
    if actual != head_sha:
        print(f"skipping: PR #{pr_number} has moved on ({actual[:12]} != {head_sha[:12]})")
        return None

    kept = [x for x in labels if x in ALLOWED_LABELS]
    dropped = sorted(set(labels) - set(kept))
    if dropped:
        print(f"dropped labels outside the allowlist: {dropped}")

    if len(body) > MAX_BODY:
        body = body[:MAX_BODY] + "\n\n_(truncated)_"
    return pr_number, body, kept


def upsert_comment(pr_number: str, body: str) -> None:
    body = f"{MARKER}\n{body}"
    status, comments = gh_api(f"repos/{REPO}/issues/{pr_number}/comments?per_page=100")
    existing = None
    if status == 200 and isinstance(comments, list):
        for c in comments:
            if MARKER in (c.get("body") or "") and (c.get("user") or {}).get("type") == "Bot":
                existing = c.get("id")
                break

    if existing:
        status, resp = gh_api(f"repos/{REPO}/issues/comments/{existing}",
                              method="PATCH", data={"body": body})
        action = "updated"
    else:
        status, resp = gh_api(f"repos/{REPO}/issues/{pr_number}/comments",
                              method="POST", data={"body": body})
        action = "posted"

    if status >= 300:
        print(f"comment {action} failed: {status} {resp}", file=sys.stderr)
    else:
        print(f"{action} review comment on #{pr_number}")


def sync_labels(pr_number: str, labels: list[str]) -> None:
    """Apply the run's labels and clear stale auto/* ones from earlier runs."""
    status, current = gh_api(f"repos/{REPO}/issues/{pr_number}/labels")
    have = {l.get("name") for l in current} if status == 200 and isinstance(current, list) else set()

    for lab in labels:
        if lab in have:
            continue
        status, resp = gh_api(f"repos/{REPO}/issues/{pr_number}/labels",
                              method="POST", data={"labels": [lab]})
        if status >= 300:
            print(f"label apply failed ({lab}): {status} {resp}", file=sys.stderr)

    for lab in have & ALLOWED_LABELS:
        if lab not in labels:
            gh_api(f"repos/{REPO}/issues/{pr_number}/labels/{lab.replace('/', '%2F')}",
                   method="DELETE")
    print(f"labels now: {labels}")


def main() -> int:
    if not TOKEN or not REPO:
        print("missing GITHUB_TOKEN / GITHUB_REPOSITORY", file=sys.stderr)
        return 1

    payload = load_payload()
    if payload is None:
        return 0
    checked = validate(payload)
    if checked is None:
        return 0

    pr_number, body, labels = checked
    upsert_comment(pr_number, body)
    sync_labels(pr_number, labels)
    return 0


if __name__ == "__main__":
    sys.exit(main())
