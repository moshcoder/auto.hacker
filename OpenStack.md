# OpenStack — auto.hacker

Built with the Profullstack house stack:

- **Runtime:** Bun + TypeScript
- **Web:** Hono
- **Storage:** SQLite (bun:sqlite)
- **Auth:** magic-link email (one-time links), account API keys (`ah_…`)
- **Scan engine:** ThreatCrush pentest suite (vendored, non-destructive GET/probe checks)
- **Signup fields:** @profullstack/profile
- **Footer / webring:** @profullstack/footer (Profullstack ring) + the pit.world global footer
- **Payments:** @profullstack/coinpay-onboard (CoinPay; no Stripe)
- **Email:** Resend
- **Surfaces:** Web (PWA), JSON API, CLI (`autohacker`), MCP server, TUI (@profullstack/hqtui)
- **Host:** a Moshpit name on the pit.world network (auto.hacker.pit.world)
