Appreciate and recognize [all contributors](https://github.com/qazbnm456/awesome-web-security/graphs/contributors).

Please note that this project is released with a [Contributor Code of Conduct](https://github.com/qazbnm456/awesome-web-security/blob/master/code-of-conduct.md). By participating in this project you agree to abide by its terms.

# Table of Contents

- [How contributions are reviewed](#how-contributions-are-reviewed)
- [Two ways to contribute](#two-ways-to-contribute)
- [Editing the data](#editing-the-data)
- [Quality standard](#quality-standard)
- [Pull request guidelines](#pull-request-guidelines)
- [Maintainer notes](#maintainer-notes)

# How contributions are reviewed

Every PR is graded by the auto-review bot against [RUBRIC.md](RUBRIC.md): a
five-dimension score covering reachability, format conformance, content depth,
category fit, and dedup risk. The bot's score is advisory — the maintainer
makes the final merge decision. Disagree with the bot? Reply on the PR and
tag `@qazbnm456`.

# Two ways to contribute

> **Note:** this repo migrated to a YAML-first data model in early 2026.
> Direct `README.md` edits no longer land cleanly — CI checks that the
> generated READMEs match the YAML source. If you have a pre-migration
> PR open, no action needed: we'll port your entry on your branch when
> the backlog reaches it, so your PR can still merge with full
> attribution intact.

**1. Open an issue with the proposal form.**
Faster for one-off suggestions. Use the
[Propose a Resource](../../issues/new?template=propose-resource.yml) form;
the maintainer (or an AI agent) can turn it into a PR.

**2. Open a pull request directly.**
Edit `data/entries/<category>.yml` to add or modify an entry. The README files
are auto-generated from those YAML files; do not edit them by hand.

(your commit message will be a tweet, keep that in mind :)

# Editing the data

The three language READMEs (`README.md`, `README-zh.md`, `README-jp.md`) are
**generated** from `data/categories.yml` and `data/entries/*.yml`. Edit only
the YAML; the generator writes the Markdown.

Each entry looks like:

```yaml
- id: xss-google-app-security
  url: https://www.google.com/intl/sw/about/appsecurity/learning/xss/
  title: Cross-Site Scripting – Application Security – Google
  author:
    name: Google
    url: https://www.google.com/
  category: xss
  type: article          # article | tool | cheatsheet | video | book | community | payload-list
  languages: [en]        # en | zh | jp | tr | universal
  difficulty: intro      # intro | intermediate | advanced
  date_added: 2017-01-29
  status: active         # active | dead | archived-only | quarantined
```

Run `python3 scripts/generate.py` locally to regenerate the READMEs from your
changes, and `python3 scripts/verify_schema.py` to validate. CI runs both
automatically.

# Quality standard

Entries on this list should:

- Be reachable (2xx, HTTPS preferred, no redirect chain).
- Solve a real problem or teach a real technique. Marketing pages, lead-gen,
  and paywalled stubs are out.
- Carry non-trivial depth: original research, reproducible PoC, hands-on
  examples, or a comprehensive payload list.
- Fit the category they claim.
- Not duplicate an existing entry. Search first.

Read [RUBRIC.md](RUBRIC.md) for the exact scoring criteria the bot applies.

# Pull request guidelines

- Make a separate PR for each resource. Don't bundle.
- Use a clear PR title (the commit message will be a tweet).
- The PR body should explain *why* — what gap does this entry fill, what
  angle does it bring that existing entries don't.
- If you want to propose without writing YAML, use the issue form instead.
- Trailing whitespace, mixed line endings, and broken anchors are rejected by
  CI; please run `python3 scripts/verify_anchors.py` if you change category
  structure.

# Maintainer notes

## Porting a legacy README-shape PR

Some PRs predate the YAML migration and edit `README.md` directly. To
merge those while preserving the contributor's authorship signal:

1. `gh pr checkout <N>` — fetches the contributor's fork branch.
2. `python3 scripts/ci/port_legacy_pr.py <N>` — extracts title / URL /
   description from the diff and emits a YAML entry stub. The script
   also prints a `Co-authored-by:` trailer with the contributor's
   numeric GitHub ID, ready for the squash-merge body.
3. `git merge master --no-edit` — brings the YAML data model into the
   branch. Resolve the inevitable `README.md` conflict by taking
   `master`'s version: `git checkout --ours README.md && git add
   README.md && git commit --no-edit`. The contributor's hand-edited
   line is implicitly superseded because the README is now generated.
4. Add the new entry to `data/entries/<category>.yml` using the script's
   stub, then run `python3 scripts/generate.py` and the verify scripts.
5. Commit the port and push to the contributor's fork:
   `git push <fork-url> <branch>:<branch>`.
6. Once CI is green, squash-merge via `gh pr merge <N> --squash` with
   an explicit `--subject` and a `--body` that ends with the
   `Co-authored-by:` trailer.

GitHub's squash-merge picks the first commit's author (the contributor)
as the squash commit's primary author, so the contributor keeps their
**Merged PRs** counter, the **merged** badge on the PR, and primary
authorship of the merge commit on `master`. The `Co-authored-by:`
trailer is belt-and-braces credit.

Note: the PR auto-review bot does not post comments on PRs from forks
— GitHub silently downgrades `GITHUB_TOKEN` to read-only for
`pull_request` events from forks, and this repo intentionally does not
use `pull_request_target` (security-sensitive). The bot still grades
internally for the workflow log; the maintainer's manual review during
port covers the same rubric dimensions.

Thanks for contributing!
