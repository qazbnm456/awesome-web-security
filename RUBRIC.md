# Review Rubric

How the auto-review bot (and the maintainer) grade proposed entries.

Every contribution is scored across five dimensions, 0–3 each (max 15).
The bot's score is advisory — only the maintainer merges. Contributors
can see this rubric to self-check before opening a PR.

## Dimensions

### 1. Reachability

Does the URL resolve, and how cleanly?

| Score | Meaning |
|---|---|
| **3** | 2xx HTTPS direct, no redirects |
| **2** | 2xx HTTPS with at most one redirect within the same domain |
| **1** | HTTP (not HTTPS) but 2xx, or 2+ redirect hops |
| **0** | 4xx / 5xx / timeout / DNS failure |

### 2. Format conformance

Does the YAML entry match the schema in `CLAUDE.md`?

| Score | Meaning |
|---|---|
| **3** | All required fields present, optional fields filled where applicable |
| **2** | All required fields present, type/language/difficulty all valid |
| **1** | All required fields present but some values out of allowed enum |
| **0** | Missing required field, malformed YAML, or invalid `category` |

### 3. Content depth

How substantive is the linked resource?

| Score | Meaning |
|---|---|
| **3** | Original research, novel technique, complex examples with refs, or a comprehensive payload list |
| **2** | Tutorial with concrete examples, code snippets, or hands-on demos |
| **1** | Intro-level overview with minimal examples |
| **0** | Marketing page, lead-gen form, paywalled stub, or thinly-disguised ad |

### 4. Category fit

Does the entry belong in the category claimed by `category:` in the YAML?

| Score | Meaning |
|---|---|
| **3** | Exact topical match, fills a gap in the category |
| **2** | Topical match, similar coverage to existing entries |
| **1** | Tangentially related; could fit a sibling category better |
| **0** | Wrong category |

### 5. Dedup risk

How similar is this to existing entries in the same category?

| Score | Meaning |
|---|---|
| **3** | Cosine similarity < 0.70 to nearest neighbor |
| **2** | 0.70 ≤ cosine < 0.85 |
| **1** | 0.85 ≤ cosine < 0.92 — strong overlap |
| **0** | cosine ≥ 0.92 — near-duplicate |

(The bot computes cosine on entry title + scraped page summary using a
multi-lingual embedding model. See `scripts/ci/pr_review.py`.)

## Score thresholds

| Total / 15 | Label | Bot action |
|---|---|---|
| ≥ 11 | `auto/format-ok` | Friendly summary, ready for maintainer review |
| 7–10 | `auto/needs-format-fix` | Lists which dimensions are weak with specific suggestions |
| < 7 | `auto/needs-major-revision` | Lists blocking issues; maintainer will likely request changes |

If any individual dimension scores `0`, the bot adds the corresponding
blocking label:

- Reachability 0 → `auto/link-broken`
- Dedup 0 → `auto/dedup-candidate`

## Appeals

The score is advisory. If you disagree:

- Reply on the PR explaining why.
- Tag `@qazbnm456`.
- The maintainer overrides the bot when context matters more than the rubric.

The bot does **not** auto-reject or auto-merge.

## Why these dimensions

- **Reachability** — broken links are the most common reason awesome-lists
  decay. Catching them at PR time is cheaper than a quarterly cleanup.
- **Format** — keeps the data clean so the JSON index for AI agents stays
  reliable.
- **Depth** — the list is for learning. Promotional or shallow content
  dilutes that purpose.
- **Category fit** — readers navigate by category. Misfiled entries make
  the list harder to use.
- **Dedup** — avoids the list growing with near-duplicates that add bytes
  but no value.
