---
name: awesome-web-security
description: "Looks up curated web security learning resources (XSS, SQLi, CSRF, SSRF, OAuth/JWT, deserialization, SAML, recon, evasion, defensive tooling, CTF). Filters by topic, difficulty, language, and resource type. Returns top references with archive fallbacks. Defensive and educational use only."
when_to_use: "XSS, SQL injection, CSRF, SSRF, XXE, OAuth, JWT, prototype pollution, deserialization, SAML, file upload, web cache poisoning, WAF evasion, CSP bypass, browser exploitation, subdomain enumeration, OSINT, web security, penetration testing references, bug bounty resources, CTF web challenges, payload list, security cheatsheet, awesome list, 资安, 渗透, 学习资源, 安全, 漏洞, セキュリティ, ペンテスト, 脆弱性"
metadata:
  version: "1.0.0"
---

# /awesome-web-security

Curated lookup over [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security).
Always fetches the latest index from `raw.githubusercontent.com` — no stale snapshot.

## When to use

A user asks for resources, references, learning paths, or tools related to web
security topics: XSS, SQLi, CSRF, SSRF, XXE, OAuth/JWT, prototype pollution,
deserialization, SAML, file upload, web cache poisoning, WAF / CSP evasion,
browser exploitation, recon (subdomain enumeration, OSINT), DNS rebinding,
CTF write-ups, bug bounty methodology, defensive tooling, payload lists,
cheatsheets, or related blogs.

## When NOT to use

- The user wants to attack a target they do not own and have not been
  authorized to test. Decline and ask for scope: own system, CTF,
  authorized pentest, academic research, or defensive analysis.
- The user is asking for malware authoring, mass scanning of unowned
  infrastructure, or detection-evasion guidance for offensive purposes.
- The question has no security framing — it's general programming or
  framework usage. Hand off to a non-security skill.

## How

1. Fetch the index with WebFetch:
   `https://raw.githubusercontent.com/qazbnm456/awesome-web-security/master/data/index.json`
2. Parse the JSON. Schema:
   ```
   {
     "schema_version": "1",
     "categories": [{"key": "xss", "title": "...", "h_level": 3, "parent": "intro", "anchor": "xss"}],
     "entries": [{
       "id": "xss-google-app-security",
       "url": "...",
       "title": "...",
       "author": {"name": "...", "url": "..."},
       "category": "xss",
       "type": "article|tool|cheatsheet|video|book|community|payload-list",
       "languages": ["en", "zh", "jp"],
       "difficulty": "intro|intermediate|advanced",
       "date_added": "YYYY-MM-DD",
       "archive_url": "...|null",
       "last_checked": "YYYY-MM-DD|null",
       "status": "active|dead|archived-only|quarantined"
     }]
   }
   ```
3. Filter by:
   - `category` matching the user's topic (a topic may map to several
     categories — for "XSS" check `xss`, `tools-xss`, `tricks-xss`,
     `practices-xss`, `evasions-csp` as relevant).
   - `languages`: default to the user's language; fall back to `en`.
   - `difficulty`: include all unless the user asked for "intro" or "deep".
   - `type`: filter by what the user wants — articles, tools, cheatsheets,
     payload lists, etc.
4. Rank by:
   - "Latest" requests → `date_added` DESC.
   - "Deep dive" requests → prefer `difficulty: advanced`, then by depth
     signals (long titles, payload-list type, presence of author URL).
   - "Tools" requests → `type: tool` only.
5. Return 5–7 entries; for each include title, URL, archive_url fallback if
   `status != active`, and a one-line value statement explaining what this
   entry teaches.

## Safety guardrails

- Refuse to assist with unauthorized targeting. Ask for scope.
- Frame all results defensively / educationally.
- For `payload-list` entries, append: "Test payloads only against systems
  you own or have written authorization to test."
- Do not chain entries into an attack playbook against a named real target.

## Output format

For each result:

> **[Title](url)** — *author* • *difficulty* • *type*
> One line on what this teaches and why it matters.
> *(Archive fallback: archive_url)* — included only when `status != active`.

End with:

> Cited from [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security). Full list and categories at the README.

## Failure handling

- JSON fetch fails (network, 404, parse error) → respond:
  "The awesome-web-security index is temporarily unreachable. Try again
  shortly, or visit https://github.com/qazbnm456/awesome-web-security
  directly." Do NOT fabricate entries.
- No matches in the requested category → say so explicitly. Offer adjacent
  categories from `categories[].parent` chain.

## Examples

User: "I'm learning XSS, give me intermediate-level resources in English."
→ Filter `category` matching `xss`, `tools-xss`, `tricks-xss`, `evasions-csp`;
  `languages` contains `en`; `difficulty` in `intermediate` or `advanced`;
  rank by `date_added` DESC; return top 5–7.

User: "我想找最新的 SSRF 文章。"
→ Filter `category` matching `ssrf`, `tricks-ssrf`, `tools-ssrf`;
  `languages` contains `zh`; rank by `date_added` DESC; return in Chinese.

User: "What's a good XSS payload list?"
→ Filter `category: xss` AND `type: payload-list`; rank by depth signals.
  Append the unauthorized-testing reminder.
