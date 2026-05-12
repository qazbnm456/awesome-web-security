Appreciate and recognize [all contributors](https://github.com/qazbnm456/awesome-web-security/graphs/contributors).

Please note that this project is released with a [Contributor Code of Conduct](https://github.com/qazbnm456/awesome-web-security/blob/master/code-of-conduct.md). By participating in this project you agree to abide by its terms.

# Table of Contents

- [How contributions are reviewed](#how-contributions-are-reviewed)
- [Two ways to contribute](#two-ways-to-contribute)
- [Editing the data](#editing-the-data)
- [Quality standard](#quality-standard)
- [Pull request guidelines](#pull-request-guidelines)

# How contributions are reviewed

Every PR is graded by the auto-review bot against [RUBRIC.md](RUBRIC.md): a
five-dimension score covering reachability, format conformance, content depth,
category fit, and dedup risk. The bot's score is advisory — the maintainer
makes the final merge decision. Disagree with the bot? Reply on the PR and
tag `@qazbnm456`.

# Two ways to contribute

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

Thanks for contributing!
