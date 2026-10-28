# auto.hacker

**Authorized, non-destructive website pentests — for sites you have proven you own.**

auto.hacker runs a security scan (missing headers, reflected-XSS markers, CORS,
cookie flags, CSP, directory listing, error disclosure, sensitive paths, unsafe
HTTP methods, SQLi/traversal probes) against a website. It will not touch a host
until the signed-in user has **proven they control that exact host**, and the
proof is re-checked at scan launch and again in the worker right before the first
request. The engine is [ThreatCrush](https://github.com/profullstack/threatcrush).

Live: https://auto.hacker.pit.world

## The ownership gate (the one rule)

No scan reaches the engine until a per-user-per-host proof is found live. Token:
`HMAC(secret, "<user_id>:<host>")`. Publish **one**:

- **DNS TXT** — `_autohacker.<host>` = `autohacker-verify=<token>`
- **File** — `https://<host>/.well-known/autohacker-<token>.txt` containing the token
- **Meta** — `<meta name="autohacker-verify" content="<token>">` on the homepage

A host you cannot prove you own is refused. Every verification appends an immutable
authorization log row. See [the manifesto](https://auto.hacker.pit.world/manifesto).

## Surfaces

- **Web** (PWA): add target, proof + verify, launch scan, live SSE run stream, history, CSV/JSON export, account/profile.
- **API**: `GET/POST /api/v1/targets`, `/targets/:id/verify`, `POST /api/v1/runs`, `/runs/:id`, `/runs/:id/stream` (SSE), `/runs/:id/export.{json,csv}`, `GET /api/v1/me/profile` (401 logged out). Bearer `ah_…`.
- **CLI**: `autohacker add|proof|verify|scan|runs|report|targets|webhooks|webhook`.
- **MCP**: `autohacker mcp` (add_target, get_proof, verify, scan, runs, report, targets, list_webhooks, create_webhook, test_webhook, rotate_webhook_secret, delete_webhook, webhook_deliveries).
- **TUI**: `autohacker tui`.

## Webhooks

Customer webhooks via [`@profullstack/webhooks`](https://github.com/profullstack/webhooks): add a URL on
`/account#webhooks`, with `autohacker webhook add <url> [events...]`, MCP `create_webhook`, or
`POST /api/v1/webhooks`. auto.hacker POSTs signed CloudEvents (Standard Webhooks) for `target.verified`,
`run.started`, `run.completed`, `run.failed`, `run.refused` and `finding.created`, to the account that owns
the target, retried for about three days. `finding.created` carries severity and the check's title only,
never the probe payload, probed URL or raw details.

## Realtime + scheduled

A run streams live over SSE. A verified host can be subscribed to periodic
(daily/weekly/monthly) scans; the worker runs them and emails a summary (Resend).
Scheduled scans are the paid tier (CoinPay); on-demand scans of your own verified
sites are free.

## Honest scope

Authorized testing of your own verified properties, non-destructive checks only.
Not a substitute for a manual penetration test.

## Develop

```
bun install
AUTOHACKER_KEY=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n') bun src/server.ts
bun test        # the ownership gate is the first and most-tested thing here
```

MIT.
