# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this repo is

A curated knowledge base of web security learning resources. Data lives in
`data/categories.yml` and `data/entries/*.yml`; the three language READMEs
(`README.md`, `README-zh.md`, `README-jp.md`) and `data/index.json` are
**generated** from that data by `scripts/generate.py`. The same data backs a
Claude Skill at `skills/awesome-web-security/` so AI agents can query the
list at runtime.

No build, no test suite, no application runtime. Every change is either
YAML data, Python tooling, or Markdown docs.

## Files of note

- `data/categories.yml` — section tree, anchors, ToC. Edit carefully.
- `data/entries/*.yml` — one file per section. Source of truth for entries.
- `data/templates/preamble.md` / `postamble.md` — verbatim header/footer in
  the generated READMEs.
- `scripts/generate.py` — YAML → README.md / README-zh.md / README-jp.md /
  data/index.json.
- `scripts/migrate.py` — one-shot importer that originally produced the YAML
  from the old hand-edited READMEs. Kept for reference; do not re-run on a
  populated `data/`.
- `scripts/verify_schema.py` — entry schema validation; CI gate.
- `scripts/verify_anchors.py` — ensures no anchor used by external links is
  removed; CI gate.
- `scripts/verify_skill.sh` — lints `marketplace.json` and `SKILL.md`.
- `scripts/ci/pr_review.py` — auto-review bot. **The LLM half is currently
  dead**: it called GitHub Models, which GitHub retired on 2026-07-30, so the
  bot has been running deterministic-only (reachability + format + local
  dedup) and reports Depth/Fit as "skipped". Choosing a replacement backend
  is deliberately deferred. Contributor language is detected
  deterministically (Han / Kana regex on PR body) and passed to the LLM
  as a directive; the LLM never owns language detection.
- `scripts/ci/publish_review.py` — the privileged half of the review pair.
  Reads the artifact `pr_review.py` produced, validates it (head SHA must
  match both the producing run and the PR's current head, labels filtered
  against an allowlist, body capped) and upserts one marked comment.
- `scripts/ci/templates/comment.{en,zh,jp}.md` — localized review comments.
- `.github/workflows/pr-review.yml` — grades a PR; never posts. Two jobs:
  `verify` runs the PR's own code, `grade` runs the trusted base-branch
  scripts over the PR's files as data and uploads the result as an artifact.
- `.github/workflows/pr-review-publish.yml` — posts that artifact from
  `workflow_run` (base-repo context, write token, never checks out the PR).
  This split exists because fork PRs get a read-only `GITHUB_TOKEN`, so the
  old single-workflow bot silently 403'd on every fork PR — which is nearly
  all of them.
- `.github/workflows/diff-sentry.yml` — `qazbnm456/diff-sentry` scan of the PR
  diff for obfuscated payloads, exfiltration sinks, bidi/zero-width evasion
  and workflow misconfigurations. Fails on `high` and above.
- `.github/workflows/pr-review-backlog.yml` — dry-run over open PRs (manual,
  workflow_dispatch). Stashes trusted scripts to `/tmp/awsec-trusted/` before
  iterating PR refs, so `pr_review.py` always runs from the base branch even
  when an attacker-controlled PR is checked out.
- `.github/workflows/health-link-check.yml` — daily lychee scan over the
  generated READMEs and `data/index.json`; surfaces broken links via a single
  rolling issue labelled `health/link-check`. Replaces the previous
  `validate.yml`.
- `.github/workflows/post-merge-archive.yml` — after merges that touch
  `data/entries/**`, submits eligible entries (active, no `archive_url` yet,
  not opted out) to Wayback Machine and commits the resulting `archive_url`
  back to the YAML with `[skip ci]`. Driven by `scripts/ci/archive.py`.
- `.github/ISSUE_TEMPLATE/propose-resource.yml` — GitHub Form for proposals.
- `.github/PULL_REQUEST_TEMPLATE.md` — self-checklist mirroring RUBRIC.md.
- `.claude-plugin/marketplace.json` — declares the Claude plugin / Skill
  package distributed via this repo.
- `skills/awesome-web-security/SKILL.md` — the Skill body. Lives here so the
  same repo serves humans and AI agents.
- `RUBRIC.md` — the five-dimension scoring rubric the bot applies; also the
  contributor self-check reference.
- `CONTRIBUTING.md` — contributor flow. Treat as authoritative for PR
  procedure; do not duplicate its contents here.

## Editing rules

- **Never edit `README.md`, `README-zh.md`, or `README-jp.md` directly.**
  They are regenerated from `data/` by `scripts/generate.py`. Edits will be
  blown away on the next regeneration.
- To add or modify an entry, edit `data/entries/<category>.yml`.
- To add a new category, edit `data/categories.yml` first, then add a new
  `data/entries/<category-key>.yml`. Run `scripts/verify_anchors.py`
  afterwards to confirm no external-facing anchor was lost.
- After any data change, run `python3 scripts/generate.py` to refresh the
  generated files locally before committing. CI will reject divergence.

## Entry schema

```yaml
- id: xss-google-app-security                   # kebab-case, unique
  url: https://www.google.com/...               # required, https preferred
  title: Cross-Site Scripting – Application Security – Google
  author:
    name: Google                                # required if author exists
    url: https://www.google.com/                # optional
  category: xss                                 # must exist in categories.yml
  type: article                                 # article|tool|cheatsheet|video|book|community|payload-list
  languages: [en]                               # subset of: en|zh|jp|tr|universal
  difficulty: intro                             # intro|intermediate|advanced
  date_added: 2017-01-29                        # ISO date
  archive_url: null                             # filled by post-merge-archive workflow
  last_checked: null                            # filled by weekly-health workflow
  fingerprint: null                             # content fingerprint, filled by health
  status: active                                # active|dead|archived-only|quarantined
```

Optional fields:

- `raw_rest` is the README description text that follows the title link
  (the generator emits `- [Title](url) - {raw_rest}.`). It is **public-facing,
  third-party-readable** content; treat it like user-facing copy.
  - DO include: a one-sentence factual description of what the resource is,
    optionally followed by a `Written by [Author](url)` byline.
  - DO NOT include: references to this project, issue/PR numbers, phrases
    like "originally proposed by", or any internal metadata. Git history
    already preserves attribution; a third-party reader of the README must
    not infer that the entry has any historical relationship to this repo.
  - Leave migrator-written values as-is; only rewrite when the original is
    wrong or stale.
- `archive_opt_out: true` skips Wayback Machine archiving for this entry.
  Set this only when the original author has explicitly asked not to be
  archived (paywalled content, takedown requests). Defaults to false.
- `languages: [universal]` is a wildcard meaning "render this entry in
  every language README". Use sparingly; prefer explicit `[en, zh, jp]` when
  you know the audience exactly.

## Anchor preservation

External sites and the ToC both link to `#some-anchor` targets. Renaming or
removing an existing anchor silently breaks those links. The CI guard
`scripts/verify_anchors.py` compares the working tree's anchor set against
master and fails the build if any baseline anchor is missing. Never rename
an existing anchor; always add new ones for new sections.

## Language policy

Project-authored content is English. Exceptions, where multi-language is
intrinsic to the artifact:

- `README-zh.md`, `README-jp.md` — translated versions of `README.md`.
- `data/categories.yml` `title_zh` / `title_jp` overrides, if any are added
  later (currently the section titles are uniform across languages).
- `data/entries/*.yml` `title` and `notes` fields preserve the resource's
  original language (e.g. a Chinese article keeps its Chinese title).
- `skills/awesome-web-security/SKILL.md` `when_to_use` trigger phrases use
  multi-lingual keywords so the skill activates on non-English prompts.
  The SKILL.md body itself remains English.
- `scripts/ci/templates/comment.{en,zh,jp}.md` — the auto-review bot replies
  in the contributor's language when detected with high confidence, falling
  back to English otherwise. Dimension names (`Reachability`, `Format`,
  `Depth`, `Fit`, `Dedup`) stay in English; they are keys into RUBRIC.md.

Everything else — code, comments, schema field names, templates, CI output,
labels, commit messages — is English.

## Multi-language entry routing

A single entry can appear in multiple READMEs. The `languages` field
controls where it shows up:

- New entry, no language hint from the contributor → put it in `[en]` only;
  ask the contributor if they want it in `zh` / `jp` too.
- Locale-specific resource (Chinese-language article, Japanese-only forum) →
  use `[zh]` / `[jp]` only.
- Truly cross-cultural canonical resource → `[en, zh, jp]` or `[universal]`.
- Do not force-translate or force-mirror an entry across languages to
  "match" the structure. Each README is allowed to have entries the others
  don't.

## Handling new resource requests

Two kinds of inbound requests, both ported into the YAML data model
the same way the 2026 backlog was cleared:

**Issue Form submission** (`.github/ISSUE_TEMPLATE/propose-resource.yml`)
— the contributor filed an issue, not a PR. Port it directly: add the
entry to `data/entries/<category>.yml`, run `python3
scripts/generate.py` and the verify scripts, commit to `master` with
`Closes #<n>` and a `Co-authored-by:` trailer crediting the submitter.
They never had a branch, so the co-author trailer is their credit.

**Direct pull request** (contributor edited `README.md` or the YAML
directly) — port on *their* branch so their PR merges with full
attribution. See CONTRIBUTING.md "Maintainer notes" for the six-step
Path B playbook. Never route a direct PR through Copilot: Copilot
opens its own PR and closes the contributor's unmerged, destroying
their merged-PR credit.

### Copilot as async fallback

Copilot is the fallback for **Issue Form submissions only**, when the
maintainer is unavailable for an extended period and the queue needs
to keep moving. It is not the standard workflow — the manual port
above is. The maintainer still reviews the resulting Copilot PR before
merge; Copilot saves the typing, not the judgment. Prompt shape:

```
@copilot please port this resource into the new YAML data model.

Add it to `data/entries/<TARGET>.yml` with:
- url, title, author.name, author.url (from the issue fields)
- type: <article|tool|cheatsheet|video|book|community|payload-list>
- difficulty: <intro|intermediate|advanced>
- languages: [en, zh, jp] unless the resource is locale-specific
  (then [zh] or [jp]); never [universal] as the sole value without
  confirming with the maintainer
- status: active

Set `raw_rest` to a one-sentence factual description of the resource
itself, optionally followed by a `Written by [Author](url)` byline. Do
NOT mention this project, the issue number, the PR number, or any
internal metadata in `raw_rest`.

End the PR body with both:
  Closes #<n>
  Co-authored-by: <issue-author> <ID+login@users.noreply.github.com>

Run `python3 scripts/generate.py` and `python3 scripts/verify_schema.py`
before opening the PR.
```

Adjust `<TARGET>`, `type`, `difficulty`, `languages`, the issue
number, and the co-author identity per case.

## Things not to do

- Do not edit the generated `README*.md` files directly.
- Do not rename or remove existing anchors in `data/categories.yml`.
- Do not introduce HTML tags in `data/templates/*.md` beyond `a, b, br, p,
  img` (the project's markdownlint config).
- Do not bulk-reorder existing entries — the generator sorts by
  `date_added`, then by title. To move an entry up, change its
  `date_added`.
- Do not commit `data/index.json` edits by hand. It is fully regenerated by
  `scripts/generate.py`.
- Do not edit `CONTRIBUTING.md`, `code-of-conduct.md`, or workflow files
  unless the user explicitly asks.
- Do not create commits or push unless explicitly asked.

## CI behavior

On every PR touching `data/**`, a generated README, or the generator
scripts:

1. Runs `verify_schema.py` and `verify_anchors.py`.
2. Re-runs `generate.py` and warns if the working tree diverges from the
   generated output (contributor forgot to regenerate).
3. Grades each new entry against RUBRIC.md and writes the verdict to an
   artifact. A PR that only edited a generated README is graded too: the bot
   reports link reachability plus the YAML-first explanation, in the
   contributor's language.
4. `pr-review-publish.yml` picks that artifact up on `workflow_run` and posts
   a single structured comment, replacing its own previous one, then syncs
   the advisory labels.

Every PR, path-filtered or not, is also scanned by diff-sentry.

The bot never auto-merges and never auto-rejects.

## When in doubt

Match the spirit of CONTRIBUTING.md and RUBRIC.md. Ask the user if a change
crosses into territory not described here (new language version, new entry
schema field, new section taxonomy).
