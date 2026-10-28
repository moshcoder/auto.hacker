/**
 * The auto.hacker web server: pages, the JSON API, the SSE run stream and the
 * CoinPay webhook. auto.hacker is a Moshpit name — visitors on Moshpit DNS reach
 * https://auto.hacker directly; everyone else comes through the pit.world relay
 * at https://auto.hacker.pit.world, which is the address we hand out.
 */
import { Hono, type Context } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { streamSSE } from 'hono/streaming'
import { validateProfile, createProfileStore } from '@profullstack/profile'
import { webhooksApi, WebhookError } from '@profullstack/webhooks'
import { Store, type User } from './db.ts'
import { Auth, consoleMailer, resendMailer, safeNext, SESSION_COOKIE, validEmail, type Mailer } from './auth.ts'
import { AutoHacker, InputError, WEBHOOK_EVENTS, type Config } from './service.ts'
import { OwnershipError, type Method } from './gate.ts'
import { Worker } from './worker.ts'
import { startPitFooterRefresh } from './pit-footer.ts'
import { ringFooterOptions, setRingFooterOptions, startRingFooterRefresh } from './ring-footer.ts'
import { RING_PLACEHOLDER, ringBar, startRingRefresh, visitorOnMoshpit } from './ring.ts'
import { accountPage, esc, homePage, layout, loginPage, manifestoPage, messagePage, runPage, runsPage, targetPage, targetsPage, type Ctx } from './html.ts'
import { VERSION } from './version.ts'

export { VERSION }
const SELF = 'auto.hacker'
export const PUBLIC_ORIGIN = 'https://auto.hacker.pit.world'

const CSP = [
  "default-src 'none'", "style-src 'self' 'unsafe-inline'", "script-src 'self' 'unsafe-inline' https://crawlproof.com",
  "img-src 'self' data:", "connect-src 'self' https://crawlproof.com", "manifest-src 'self'", "worker-src 'self'",
  "form-action 'self' https://coinpayportal.com", "base-uri 'none'", "frame-ancestors 'none'",
].join('; ')
const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': CSP, 'referrer-policy': 'strict-origin-when-cross-origin', 'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY', 'permissions-policy': 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
}

export type Deps = { service: AutoHacker; auth: Auth; worker: Worker; profiles: ReturnType<typeof createProfileStore>; secureCookies?: boolean; crawlproof?: string | null; selfProof?: string | null }

class Limiter {
  private hits = new Map<string, { n: number; reset: number }>()
  constructor(private max: number, private windowMs: number) {}
  allow(key: string, now = Date.now()): boolean {
    const h = this.hits.get(key)
    if (!h || h.reset < now) { if (this.hits.size > 50_000) this.hits.clear(); this.hits.set(key, { n: 1, reset: now + this.windowMs }); return true }
    h.n += 1; return h.n <= this.max
  }
}

export function createApp(deps: Deps) {
  const { service, worker, profiles } = deps
  const store = service.store
  const origin = service.config.origin
  const app = new Hono()
  const postLimit = new Limiter(40, 10 * 60_000)

  const direct = (c: Context) => visitorOnMoshpit(SELF, c.req.header('host'), c.req.header('x-moshpit-name'))
  const sessionUser = (c: Context) => deps.auth.sessionUser(getCookie(c, SESSION_COOKIE))
  const ctxOf = (c: Context): Ctx => ({ origin, user: sessionUser(c), crawlproof: deps.crawlproof ?? null, selfProof: deps.selfProof ?? null })
  const page = (c: Context, html: string, status = 200) => c.html(html.replace(RING_PLACEHOLDER, ringBar(SELF, direct(c))), status as 200)
  const here = (c: Context) => (direct(c) ? 'https://auto.hacker' : origin)
  const secure = (c: Context) => deps.secureCookies ?? (c.req.header('x-forwarded-proto') ?? 'https') === 'https'
  const bearer = (c: Context) => (c.req.header('authorization') ?? '').replace(/^Bearer\s+/i, '').trim()
  const apiUser = (c: Context): User | null => { const k = bearer(c); return k ? store.byApiKey(k) : sessionUser(c) }
  const wantsJson = (c: Context) => (c.req.header('accept') ?? '').includes('application/json')
  const crossSite = (c: Context) => { const s = c.req.header('sec-fetch-site'); return s !== undefined && s !== 'same-origin' && s !== 'none' }

  app.use('*', async (c, next) => {
    await next()
    if (!c.res.headers.has('content-security-policy')) for (const [k, v] of Object.entries(SECURITY_HEADERS)) c.header(k, v)
  })

  app.get('/health', (c) => c.json({ ok: true, version: VERSION }))

  app.get('/:file{(style\\.css|app\\.js|sw\\.js|favicon\\.svg|manifest\\.webmanifest)}', async (c) => {
    const file = c.req.param('file')
    const type = file.endsWith('.css') ? 'text/css' : file.endsWith('.js') ? 'text/javascript' : file.endsWith('.svg') ? 'image/svg+xml' : 'application/manifest+json'
    try { return c.body(await Bun.file(new URL(`../public/${file}`, import.meta.url)).text(), 200, { 'content-type': `${type}; charset=utf-8`, 'cache-control': 'public, max-age=3600' }) } catch { return c.notFound() }
  })

  // --- public pages ---
  app.get('/', (c) => page(c, homePage(ctxOf(c))))
  app.get('/manifesto', (c) => page(c, manifestoPage(ctxOf(c))))
  app.get('/docs', (c) => page(c, docsPage(ctxOf(c))))
  app.get('/robots.txt', (c) => c.text(`User-agent: *\nAllow: /\nDisallow: /targets\nDisallow: /runs\nDisallow: /account\nSitemap: ${origin}/sitemap.xml\n`))
  app.get('/sitemap.xml', (c) => c.body(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${['/', '/manifesto', '/docs', '/login'].map((p) => `<url><loc>${origin}${p}</loc></url>`).join('')}</urlset>`, 200, { 'content-type': 'application/xml; charset=utf-8' }))
  app.get('/llms.txt', (c) => c.text(`# auto.hacker\n\nAuthorized, non-destructive website pentest service. We only scan hosts the signed-in user has PROVEN they own (DNS TXT, /.well-known file, or meta tag), re-checked at every scan. Engine: ThreatCrush.\n\nSurfaces: Web, API (/api/v1), CLI (autohacker), MCP, TUI.\nManifesto: ${origin}/manifesto\nAPI docs: ${origin}/docs\n`))

  // --- auth ---
  app.get('/login', (c) => page(c, loginPage(ctxOf(c), { next: safeNext(c.req.query('next')) })))
  app.post('/login', async (c) => {
    if (crossSite(c)) return c.text('cross-site form post refused', 403)
    const form = await c.req.parseBody()
    await deps.auth.sendLink(String(form.email ?? ''), safeNext(form.next), here(c))
    return page(c, loginPage(ctxOf(c), { sent: true }))
  })
  app.get('/auth/verify', (c) => {
    const r = deps.auth.consumeLink(c.req.query('token') ?? '')
    if (!r) return page(c, messagePage(ctxOf(c), { title: 'Link expired', message: 'That sign-in link is used or expired. Ask for a new one.' }), 400)
    setCookie(c, SESSION_COOKIE, deps.auth.createSession(r.user.id), { httpOnly: true, secure: secure(c), sameSite: 'Lax', path: '/', maxAge: 90 * 86400 })
    return c.redirect(safeNext(r.next) ?? '/targets')
  })
  app.post('/logout', (c) => { deps.auth.endSession(getCookie(c, SESSION_COOKIE)); deleteCookie(c, SESSION_COOKIE, { path: '/' }); return c.redirect('/') })

  const needUser = (c: Context) => { const u = sessionUser(c); if (!u) throw new RedirectLogin(c.req.path); return u }

  // --- targets ---
  app.get('/targets', (c) => { let u: User; try { u = needUser(c) } catch { return c.redirect(`/login?next=/targets`) } return page(c, targetsPage(ctxOf(c), service.listTargets(u))) })
  app.post('/targets', async (c) => {
    if (crossSite(c)) return c.text('refused', 403)
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login?next=/targets') }
    const form = await c.req.parseBody()
    try { const t = service.addTarget(u, String(form.host ?? '')); return c.redirect(`/targets/${t.id}`) }
    catch (e) { return page(c, targetsPage(ctxOf(c), service.listTargets(u), { error: (e as Error).message })) }
  })
  const ownTarget = (c: Context, u: User) => { const t = store.target(c.req.param('id') ?? ''); return t && t.userId === u.id ? t : null }
  app.get('/targets/:id', (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login?next=/targets') }
    const t = ownTarget(c, u); if (!t) return page(c, messagePage(ctxOf(c), { title: 'Not found', message: 'No such target.' }), 404)
    return page(c, targetPage(ctxOf(c), t, service.proof(u, t.host), store.runsForTarget(t.id, 20), store.schedule(t.id), { verified: c.req.query('verified') === '1' }))
  })
  app.post('/targets/:id/verify', async (c) => {
    if (crossSite(c)) return c.text('refused', 403)
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login') }
    const t = ownTarget(c, u); if (!t) return c.notFound()
    const r = await service.verify(u, t)
    if (r.ok) return c.redirect(`/targets/${t.id}?verified=1`)
    return page(c, targetPage(ctxOf(c), store.target(t.id)!, service.proof(u, t.host), store.runsForTarget(t.id, 20), store.schedule(t.id), { error: `No proof found yet. Looked at: ${r.looked.join('; ')}` }))
  })
  app.post('/targets/:id/scan', async (c) => {
    if (crossSite(c)) return c.text('refused', 403)
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login') }
    const t = ownTarget(c, u); if (!t) return c.notFound()
    try { const run = await service.createRun(u, t); return c.redirect(`/runs/${run.id}`) }
    catch (e) { return page(c, targetPage(ctxOf(c), store.target(t.id)!, service.proof(u, t.host), store.runsForTarget(t.id, 20), store.schedule(t.id), { error: (e as Error).message }), e instanceof OwnershipError ? 403 : 400) }
  })
  app.post('/targets/:id/subscribe', async (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login') }
    const t = ownTarget(c, u); if (!t) return c.notFound()
    const form = await c.req.parseBody()
    try { service.subscribe(u, t, String(form.cadence ?? 'weekly')) } catch (e) { return page(c, targetPage(ctxOf(c), t, service.proof(u, t.host), store.runsForTarget(t.id, 20), store.schedule(t.id), { error: (e as Error).message })) }
    return c.redirect(`/targets/${t.id}`)
  })
  app.post('/targets/:id/unsubscribe', (c) => { const u = sessionUser(c); if (!u) return c.redirect('/login'); const t = ownTarget(c, u); if (t) service.unsubscribe(u, t); return c.redirect(`/targets/${t?.id ?? ''}`) })

  // --- runs + SSE ---
  app.get('/runs', (c) => { let u: User; try { u = needUser(c) } catch { return c.redirect('/login?next=/runs') } return page(c, runsPage(ctxOf(c), store.runsOf(u.id))) })
  app.get('/runs/:id', (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login?next=/runs') }
    const run = store.run(c.req.param('id') ?? ''); if (!run || run.userId !== u.id) return page(c, messagePage(ctxOf(c), { title: 'Not found', message: 'No such run.' }), 404)
    return page(c, runPage(ctxOf(c), run, store.findings(run.id)))
  })
  app.get('/api/v1/runs/:id/stream', (c) => {
    const u = apiUser(c); const run = store.run(c.req.param('id') ?? '')
    if (!u || !run || run.userId !== u.id) return c.json({ error: 'not found' }, 404)
    return streamSSE(c, async (stream) => {
      for (const e of worker.bus.backfill(run.id)) await stream.writeSSE({ event: e.type, data: JSON.stringify(e) })
      if (worker.bus.done(run.id) || (run.status !== 'queued' && run.status !== 'running')) return
      await new Promise<void>((resolve) => {
        const off = worker.bus.subscribe(run.id, (e) => {
          stream.writeSSE({ event: e.type, data: JSON.stringify(e) }).catch(() => {})
          if (e.type === 'done' || e.type === 'error' || e.type === 'refused') { off(); resolve() }
        })
        stream.onAbort(() => { off(); resolve() })
      })
    })
  })

  // --- account + profile ---
  app.get('/account', async (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login?next=/account') }
    const profile = (await profiles.get(u.id)) ?? { email: u.email }
    return page(c, accountPage(ctxOf(c), { profile: profile as any, paid: c.req.query('paid') === '1', webhooks: await service.hooks.listEndpoints(u.id) }))
  })
  // Webhooks from the account page: add, test, rotate, delete. /api/v1/webhooks does the same with a key.
  app.post('/account/webhooks/:action{(add|test|rotate|delete)}', async (c) => {
    if (crossSite(c)) return c.text('refused', 403)
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login?next=/account') }
    const form = await c.req.parseBody()
    const show = async (data: { flash?: string; webhookSecret?: string }, status = 200) => {
      const profile = (await profiles.get(u.id)) ?? { email: u.email }
      return page(c, accountPage(ctxOf(c), { ...data, profile: profile as any, webhooks: await service.hooks.listEndpoints(u.id) }), status)
    }
    if (!postLimit.allow(`wh:${u.id}`)) return show({ flash: 'Too many changes. Wait a few minutes.' }, 429)
    try {
      const action = c.req.param('action')
      if (action === 'add') {
        const r = await service.hooks.createEndpoint(u.id, { url: String(form.url ?? ''), events: String(form.events ?? '') || undefined, description: String(form.description ?? '') })
        return show({ flash: 'Webhook added. Its signing secret is below (GET /api/v1/webhooks/:id/secret shows it again).', webhookSecret: r.secret })
      }
      const id = String(form.id ?? '')
      if (action === 'test') {
        const r = await service.hooks.test(u.id, id)
        return show({ flash: r.ok ? `Test delivered (HTTP ${r.status}).` : `Test failed: ${r.error}` })
      }
      if (action === 'rotate') return show({ flash: 'New signing secret below; the old one has stopped working.', webhookSecret: (await service.hooks.rotateSecret(u.id, id)).secret })
      await service.hooks.deleteEndpoint(u.id, id)
      return show({ flash: 'Webhook removed.' })
    } catch (e) {
      return show({ flash: (e as Error).message }, e instanceof WebhookError ? e.status : 400)
    }
  })
  app.post('/account/profile', async (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login') }
    const form = await c.req.parseBody()
    const v = validateProfile({ ...form, email: u.email }, { partial: true })
    await profiles.save(u.id, v.profile)
    if (typeof v.profile.first_name === 'string') store.setDisplayName(u.id, `${v.profile.first_name ?? ''} ${v.profile.last_name ?? ''}`.trim() || null)
    return c.redirect('/account')
  })
  app.post('/account/key', (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login') }
    const profile = { email: u.email }
    return page(c, accountPage(ctxOf(c), { apiKey: store.newApiKey(u.id), profile }))
  })
  app.post('/account/checkout', async (c) => {
    let u: User; try { u = needUser(c) } catch { return c.redirect('/login') }
    try { const { url } = await service.checkout(u); return c.redirect(url) }
    catch (e) { return page(c, messagePage(ctxOf(c), { title: 'Payment unavailable', message: (e as Error).message }), 503) }
  })

  // ===== JSON API =====
  const api = (c: Context): User | null => apiUser(c)
  app.get('/api/v1/me/profile', async (c) => { const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401); return c.json({ user: { id: u.id, email: u.email }, profile: (await profiles.get(u.id)) ?? null }) })
  app.get('/api/v1/targets', (c) => { const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401); return c.json({ targets: service.listTargets(u) }) })
  app.post('/api/v1/targets', async (c) => {
    const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401)
    const body = await c.req.json().catch(() => ({})) as any
    try { const t = service.addTarget(u, String(body.host ?? '')); return c.json({ target: t, proof: service.proof(u, t.host) }, 201) }
    catch (e) { return c.json({ error: (e as Error).message }, 400) }
  })
  app.get('/api/v1/targets/:id', (c) => { const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401); const t = store.target(c.req.param('id')); if (!t || t.userId !== u.id) return c.json({ error: 'not found' }, 404); return c.json({ target: t, proof: service.proof(u, t.host), runs: store.runsForTarget(t.id, 20), schedule: store.schedule(t.id) }) })
  app.post('/api/v1/targets/:id/verify', async (c) => {
    const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401)
    const t = store.target(c.req.param('id')); if (!t || t.userId !== u.id) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json().catch(() => ({})) as any
    const r = await service.verify(u, t, body.method as Method | undefined)
    return c.json({ ...r, target: store.target(t.id) }, r.ok ? 200 : 422)
  })
  app.post('/api/v1/runs', async (c) => {
    const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401)
    const body = await c.req.json().catch(() => ({})) as any
    let t = body.target_id ? store.target(String(body.target_id)) : body.host ? service.addTarget(u, String(body.host)) : null
    if (!t || t.userId !== u.id) return c.json({ error: 'target not found' }, 404)
    try { const run = await service.createRun(u, t); return c.json({ run }, 201) }
    catch (e) { return c.json({ error: (e as Error).message, refused: e instanceof OwnershipError }, e instanceof OwnershipError ? 403 : 400) }
  })
  app.get('/api/v1/runs', (c) => { const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401); return c.json({ runs: store.runsOf(u.id) }) })
  app.get('/api/v1/runs/:id', (c) => { const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401); const run = store.run(c.req.param('id') ?? ''); if (!run || run.userId !== u.id) return c.json({ error: 'not found' }, 404); return c.json({ run, findings: store.findings(run.id) }) })
  const exportRun = (c: Context, fmt: 'json' | 'csv') => {
    const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401)
    const run = store.run(c.req.param('id') ?? ''); if (!run || run.userId !== u.id) return c.json({ error: 'not found' }, 404)
    const { body, type } = service.exportFindings(run, fmt)
    return c.body(body, 200, { 'content-type': `${type}; charset=utf-8`, 'content-disposition': `attachment; filename="autohacker-${run.host}-${run.id}.${fmt}"` })
  }
  app.get('/api/v1/runs/:id/export.json', (c) => exportRun(c, 'json'))
  app.get('/api/v1/runs/:id/export.csv', (c) => exportRun(c, 'csv'))
  // Customer webhooks: the @profullstack/webhooks API, scoped to the API key's (or session's) account.
  const hookOwner = new WeakMap<Request, string>()
  const hooksApi = webhooksApi(service.hooks, { basePath: '/api/v1/webhooks', owner: (req) => hookOwner.get(req) })
  const webhooksRoute = async (c: Context) => {
    const u = api(c); if (!u) return c.json({ error: 'unauthorized' }, 401)
    if (c.req.method !== 'GET' && !bearer(c) && crossSite(c)) return c.json({ error: 'cross-site request refused' }, 403)
    hookOwner.set(c.req.raw, u.id)
    return (await hooksApi(c.req.raw)) ?? c.json({ error: 'not found' }, 404)
  }
  app.all('/api/v1/webhooks', webhooksRoute)
  app.all('/api/v1/webhooks/*', webhooksRoute)
  app.get('/api/v1/stats', (c) => c.json({ ...store.stats(), version: VERSION }))

  app.post('/hooks/coinpay', async (c) => {
    const raw = await c.req.text()
    const r = service.webhook(raw, c.req.header('x-coinpay-signature'))
    return r.ok ? c.json({ ok: true, event: r.event }) : c.json({ error: 'bad signature' }, (r.status ?? 401) as 401)
  })

  app.notFound((c) => (c.req.path.startsWith('/api/') ? c.json({ error: 'not found' }, 404) : page(c, messagePage(ctxOf(c), { title: 'Not found', message: 'That page does not exist.' }), 404)))
  app.onError((error, c) => {
    if (error instanceof RedirectLogin) return c.redirect(`/login?next=${encodeURIComponent(error.next)}`)
    console.error(error instanceof Error ? error.stack : error)
    return c.req.path.startsWith('/api/') ? c.json({ error: 'Something went wrong.' }, 500) : page(c, messagePage(ctxOf(c), { title: 'Something went wrong', message: 'Try again in a moment.' }), 500)
  })
  return app
}

class RedirectLogin extends Error { constructor(readonly next: string) { super('login') } }

function docsPage(ctx: Ctx): string {
  const body = `<article class="prose"><h1>API</h1>
  <p>Base: <code>${esc(ctx.origin)}/api/v1</code>. Authenticate with <code>Authorization: Bearer ah_…</code> (make a key on your <a href="/account">account page</a>).</p>
  <pre># who am I (401 when logged out)
GET  /api/v1/me/profile

# targets + proof
GET  /api/v1/targets
POST /api/v1/targets                 { "host": "example.com" }   -> { target, proof }
GET  /api/v1/targets/:id
POST /api/v1/targets/:id/verify      { "method": "dns|file|meta" }  (optional)

# runs — the gate refuses an unproven host with 403
POST /api/v1/runs                    { "host": "example.com" }  or { "target_id": "…" }
GET  /api/v1/runs
GET  /api/v1/runs/:id
GET  /api/v1/runs/:id/stream         (text/event-stream, live)
GET  /api/v1/runs/:id/export.json
GET  /api/v1/runs/:id/export.csv
GET  /api/v1/stats

# customer webhooks (signed CloudEvents, Standard Webhooks)
GET    /api/v1/webhooks                 -> { endpoints, event_types }
POST   /api/v1/webhooks                 { "url": "https://…", "events": ["run.*"] }  -> { endpoint, secret }
PATCH  /api/v1/webhooks/:id             { "url", "events", "description", "enabled" }
DELETE /api/v1/webhooks/:id
POST   /api/v1/webhooks/:id/test
GET    /api/v1/webhooks/:id/secret      -> { secret }
POST   /api/v1/webhooks/:id/rotate      -> { secret }
GET    /api/v1/webhooks/:id/deliveries  (or /api/v1/webhooks/deliveries for all)</pre>
  <p>Events: ${WEBHOOK_EVENTS.map((e) => `<code>${e}</code>`).join(', ')}. <code>finding.created</code> carries the severity and the check's title only, never the probe payload or URL: fetch the run report for detail.</p>
  <p class="muted">The <code>autohacker</code> CLI and the MCP server speak the same verbs: <code>add</code>, <code>verify</code>, <code>scan</code>, <code>runs</code>, <code>report</code>, <code>webhooks</code>.</p></article>`
  return layout(ctx, { title: 'API — auto.hacker', desc: 'auto.hacker HTTP API.', body, publicPage: true })
}

export function configFromEnv(env: Record<string, string | undefined> = process.env): Config {
  const coinpay = env.COINPAY_API_KEY && env.COINPAY_BUSINESS_ID
    ? { baseUrl: (env.COINPAY_API_URL ?? 'https://coinpayportal.com').replace(/\/+$/, '').replace(/\/api$/, ''), apiKey: env.COINPAY_API_KEY, businessId: env.COINPAY_BUSINESS_ID, webhookSecret: env.COINPAY_WEBHOOK_SECRET ?? '' }
    : null
  return { origin: (env.AUTOHACKER_ORIGIN ?? PUBLIC_ORIGIN).replace(/\/+$/, ''), secret: env.AUTOHACKER_KEY ?? '', coinpay, priceUsd: Number(env.AUTOHACKER_PRICE_USD ?? 9), runCooldownMs: Number(env.AUTOHACKER_RUN_COOLDOWN_MS ?? 5 * 60_000) }
}

export function serve(options: { port?: number; hostname?: string } = {}) {
  const env = process.env
  const dataDir = env.AUTOHACKER_DATA ?? `${env.HOME}/.local/share/auto-hacker`
  const store = new Store(env.AUTOHACKER_DB ?? `${dataDir}/auto-hacker.db`, env.AUTOHACKER_KEY ?? '')
  const service = new AutoHacker(store, configFromEnv(env))
  const mailer: Mailer | null = env.RESEND_API_KEY ? resendMailer(env.RESEND_API_KEY, env.MAIL_FROM ?? 'auto.hacker <auto@pit.world>') : null
  const auth = new Auth(store, mailer ?? consoleMailer)
  const worker = new Worker(store, service, mailer, service.config.origin)
  const profiles = createProfileStore(store.db, { table: 'profiles', key: 'user_id' })
  profiles.migrate().catch((e) => console.error(`[profile] migrate: ${(e as Error).message}`))
  const app = createApp({ service, auth, worker, profiles, crawlproof: env.CRAWLPROOF_SITE ?? null, selfProof: env.AUTOHACKER_SELF_PROOF ?? null })
  startRingRefresh(); startPitFooterRefresh('auto.hacker')
  setRingFooterOptions(ringFooterOptions([{ label: 'Manifesto', href: '/manifesto' }, { label: 'API', href: '/docs' }, { label: 'ThreatCrush', href: 'https://github.com/profullstack/threatcrush' }]))
  startRingFooterRefresh()
  worker.start()
  // Customer webhooks: deliveries waiting from before the restart go out now, then every 5 s.
  service.hooks.start()
  return Bun.serve({ port: options.port ?? Number(env.PORT ?? 8793), hostname: options.hostname ?? env.HOST ?? '127.0.0.1', idleTimeout: 120, maxRequestBodySize: 1024 * 1024, fetch: app.fetch })
}

if (import.meta.main) {
  const server = serve()
  console.log(`auto.hacker listening on http://${server.hostname}:${server.port}`)
}
