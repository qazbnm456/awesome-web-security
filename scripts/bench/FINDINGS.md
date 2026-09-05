# Can a local model supply RUBRIC Depth?

Runs 33955732933 (models) and 33957150696 (truncation), on 4 vCPU public
runners, Q4_K_M, `llama.cpp` b10816. Raw results under `results/`.

## The model question — settled

| model | s/case | load | deterministic | band |
|---|---|---|---|---|
| **Ling-3.0-tiny** | 27.2 | 4.0s | yes | 8/11 |
| LFM2.5-2.6B | 100.0 | 2.0s | yes | 5/10 |
| Ornith-1.5-9B | 194.8 | 4.4s | yes | 3/4 |

Ling wins on both axes. It holds 7.9B of weights but activates 1.3B per token,
and prefill is the entire job here, so the MoE shape beats a 2.6B dense model
built for CPU by 3.7x. Ornith is out on the measurement it was included to
produce: 3.2 minutes a case.

## The truncation question — settled

18 read-verified fixtures, Ling only:

| text cap | exact | band | s/case |
|---|---|---|---|
| 10k | 10/18 | 11/18 | 42.5 |
| 24k | 11/18 | 13/18 | 71.7 |

24k is worth its extra minute: `onus-llm-stops` and `foxglove-deserialization`
both correct from 1 to 3, because at 10k the cut was removing the sections that
held the original findings.

## The verdict: do not ship a 0-3 Depth scorer

Not because 13/18 is low, but because of *why* it is low. Three feature vectors
are shared by cases carrying different labels:

```
[overview]              exp=2 excess-xss   |  exp=1 qapractices-pentest, qapractices-hub
[code overview]         exp=2 aptive-tls   |  exp=1 qapractices-xss, techbridge-csrf | exp=0 nutilz-csp
[promotional]           exp=2 laravel-csp  |  exp=1 nextjs-headers
```

Identical inputs, different correct answers. **No mapping function can separate
them**, so tuning `depth_from_features` is futile — the information needed to
tell an introductory guide with code from a hands-on tutorial with code is not
in these five booleans. That is a property of the schema, not of the model, and
it is the finding this benchmark existed to produce.

Two mapping bugs surfaced along the way, both mine, both caught by fixtures:

1. `if code and not overview: return 2` / `if code: return 2` — the second
   branch made the first one's condition dead.
2. Fixing that by sending code+overview to 1 then made Depth 2 unreachable, and
   every one of the four Depth-2 cases underscored.

## What does work: one binary flag

`presents_original_findings`, over the 15 cases the fetch actually rendered:

| text cap | caught | false alarms |
|---|---|---|
| 10k | 3/5 | 0/10 |
| 24k | **5/5** | **0/10** |

That is the judgement that most often decides a submission here — it is the
whole basis of the article-instead-of-tool path that #208, #213, #231 and #232
all took. As an advisory flag rather than a score it costs ~72s, needs no key,
and behaves identically on a fork.

Caveat worth keeping in view: five positives and ten negatives. Encouraging,
not conclusive.

## Fix before anything ships

Three of eighteen fixtures never rendered: `payloads-ssrf` (661 chars),
`mutual-tls-ssl` (1,312) and `domscan` (538). The first two are GitHub pages
whose README is loaded by JavaScript, so a plain HTML parser sees chrome. Any
production use must read github.com URLs through the API instead — and note
that the 500-character floor did not catch two of the three.
