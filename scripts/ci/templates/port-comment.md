Hi @{author}, thanks for the contribution — apologies for the long delay on this one.

This repo migrated to a YAML-first data model in early 2026 (the generated READMEs are now produced by `scripts/generate.py` from `data/entries/*.yml`), so a direct README edit no longer lands cleanly. I've ported your entry to the new format and pushed two commits to your branch:

1. **{port_commit}** — adds the entry to `data/entries/{category}.yml` and regenerates the three language READMEs + `data/index.json`.
2. **{revert_commit}** — reverts your original README.md change since the file is now auto-generated; the content is preserved in the YAML.

Your authorship is intact in the git history, and once CI goes green I'll merge — your PR will show as **merged** with full attribution.

If you'd like to adjust anything before merge (category, difficulty rating, description wording, your author URL), push to your branch and I'll re-review. Otherwise no further action needed.

For future contributions, the new flow is: edit `data/entries/<category>.yml` directly, then run `python3 scripts/generate.py`. The contributor docs in [`CONTRIBUTING.md`](https://github.com/qazbnm456/awesome-web-security/blob/master/CONTRIBUTING.md) walk through the schema.
