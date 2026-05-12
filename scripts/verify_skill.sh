#!/usr/bin/env bash
# Lint .claude-plugin/marketplace.json + skills/*/SKILL.md frontmatter.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

MANIFEST=".claude-plugin/marketplace.json"
if [ ! -f "$MANIFEST" ]; then
  echo "missing $MANIFEST" >&2
  exit 1
fi

python3 - <<'PY' || fail=1
import json, sys
m = json.load(open(".claude-plugin/marketplace.json"))
for f in ("name", "description", "owner", "plugins"):
    if f not in m:
        print(f"marketplace.json: missing `{f}`", file=sys.stderr); sys.exit(1)
if not isinstance(m["plugins"], list) or not m["plugins"]:
    print("marketplace.json: plugins must be a non-empty list", file=sys.stderr); sys.exit(1)
for p in m["plugins"]:
    for k in ("name", "description", "version", "source"):
        if k not in p:
            print(f"plugin `{p.get('name','?')}` missing `{k}`", file=sys.stderr); sys.exit(1)
print("marketplace.json: ok")
PY

for sk in skills/*/SKILL.md; do
  [ -f "$sk" ] || continue
  python3 - "$sk" <<'PY' || fail=1
import sys, re
path = sys.argv[1]
text = open(path).read()
m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
if not m:
    print(f"{path}: missing frontmatter", file=sys.stderr); sys.exit(1)
fm = m.group(1)
for f in ("name:", "description:"):
    if f not in fm:
        print(f"{path}: frontmatter missing `{f}`", file=sys.stderr); sys.exit(1)
ver = re.search(r"version:\s*\"?([\w.\-]+)\"?", fm)
if not ver:
    print(f"{path}: frontmatter missing metadata.version", file=sys.stderr); sys.exit(1)
print(f"{path}: ok (version {ver.group(1)})")
PY
done

exit $fail
