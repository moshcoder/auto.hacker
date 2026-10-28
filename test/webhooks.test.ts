import { expect, test, describe } from 'bun:test'
import { verifySignature } from '@profullstack/webhooks'
import { Store } from '../src/db.ts'
import { AutoHacker, WEBHOOK_EVENTS } from '../src/service.ts'
import { Worker } from '../src/worker.ts'
import { createApp } from '../src/server.ts'
import { Auth, consoleMailer } from '../src/auth.ts'
import type { GateDeps } from '../src/gate.ts'

const SECRET = 'z'.repeat(32)
const HOST = 'mysite.example'
const ORIGIN = 'https://auto.hacker.pit.world'

type Got = { headers: Headers; body: string; json: any }

function fresh(opts: { proof?: () => boolean } = {}) {
  let token = ''
  const proof = opts.proof ?? (() => true)
  const gate: GateDeps = { resolveTxt: async () => (proof() && token ? [[`autohacker-verify=${token}`]] : []), fetchText: async () => null }
  const got: Got[] = []
  const receiver = (async (_url: string, init: RequestInit) => {
    const body = String(init.body)
    got.push({ headers: new Headers(init.headers), body, json: JSON.parse(body) })
    return new Response('ok', { status: 200 })
  }) as unknown as typeof fetch
  const store = new Store(':memory:', SECRET)
  const service = new AutoHacker(store, { origin: ORIGIN, secret: SECRET, coinpay: null, priceUsd: 9, runCooldownMs: 0, gate, webhookFetch: receiver, webhookGuard: { lookup: async () => ['93.184.216.34'] } })
  const user = store.findOrCreateUser('owner@example.com')
  const target = service.addTarget(user, HOST)
  token = service.token(user, HOST)
  return { store, service, user, target, got }
}

const types = (got: Got[]) => got.map((g) => g.json.type)

describe('customer webhooks', () => {
  test('a verified scan sends target.verified, run.started, finding.created and run.completed, signed', async () => {
    const { store, service, user, target, got } = fresh()
    const { secret } = await service.hooks.createEndpoint(user.id, { url: 'https://hooks.example/ah' })
    const realFetch = globalThis.fetch
    // The engine's probes: every response looks like a SQL error, so the SQLi check fires with its payload in the message.
    globalThis.fetch = (async () => new Response('You have an error in your SQL syntax near', { status: 200 })) as unknown as typeof fetch
    try {
      const run = await service.createRun(user, target)
      await new Worker(store, service, null, ORIGIN).execute(run)
    } finally { globalThis.fetch = realFetch }
    await service.hooks.drain()
    const t = types(got)
    expect(t[0]).toBe('target.verified')
    expect(t.filter((x) => x === 'target.verified').length).toBe(1)   // not re-sent by the worker's re-check
    expect(t).toContain('run.started')
    expect(t).toContain('finding.created')
    expect(t[t.length - 1]).toBe('run.completed')
    for (const g of got) {
      expect(verifySignature({ secret, headers: g.headers, body: g.body }).ok).toBe(true)
      expect(g.json.source).toBe(ORIGIN)
    }
    const sqli = got.find((g) => g.json.type === 'finding.created' && g.json.data.title === 'SQL Injection')!
    expect(sqli.json.data.severity).toBe('critical')
    // Never the probe payload, location or details.
    expect(sqli.body).not.toContain("'")
    expect(Object.keys(sqli.json.data).sort()).toEqual(['finding_id', 'host', 'run_id', 'severity', 'target_id', 'title', 'url'])
    const done = got.find((g) => g.json.type === 'run.completed')!
    expect(done.json.data.counts.critical).toBeGreaterThan(0)
  })

  test('an unproven host sends run.refused, nothing else', async () => {
    const { service, user, target, got } = fresh({ proof: () => false })
    await service.hooks.createEndpoint(user.id, { url: 'https://hooks.example/ah' })
    await service.createRun(user, target).catch(() => {})
    await service.hooks.drain()
    expect(types(got)).toEqual(['run.refused'])
    expect(got[0]!.json.data.host).toBe(HOST)
  })

  test('an unreachable target sends run.failed', async () => {
    const { store, service, user, target, got } = fresh()
    await service.hooks.createEndpoint(user.id, { url: 'https://hooks.example/ah', events: ['run.*'] })
    const realFetch = globalThis.fetch
    globalThis.fetch = (async () => { throw new Error('connect ECONNREFUSED') }) as unknown as typeof fetch
    try {
      const run = await service.createRun(user, target)
      await new Worker(store, service, null, ORIGIN).execute(run)
    } finally { globalThis.fetch = realFetch }
    await service.hooks.drain()
    expect(types(got)).toEqual(['run.started', 'run.failed'])
  })

  test('another account never receives my events', async () => {
    const { store, service, user, target, got } = fresh()
    const other = store.findOrCreateUser('other@example.com')
    await service.hooks.createEndpoint(other.id, { url: 'https://hooks.example/other' })
    await service.createRun(user, target)
    await service.hooks.drain()
    expect(got.length).toBe(0)
  })

  test('/api/v1/webhooks: 401 without a key; scoped CRUD with one', async () => {
    const { store, service, user } = fresh()
    const worker = new Worker(store, service, null, ORIGIN)
    const app = createApp({ service, auth: new Auth(store, consoleMailer), worker, profiles: { get: async () => null, save: async () => {} } as any })
    expect((await app.request('/api/v1/webhooks')).status).toBe(401)
    expect((await app.request('/api/v1/webhooks', { headers: { authorization: 'Bearer ah_nope' } })).status).toBe(401)
    const key = store.newApiKey(user.id)
    const auth = { authorization: `Bearer ${key}`, 'content-type': 'application/json' }
    const list = await (await app.request('/api/v1/webhooks', { headers: auth })).json() as any
    expect(list.event_types).toEqual(WEBHOOK_EVENTS)
    const made = await app.request('/api/v1/webhooks', { method: 'POST', headers: auth, body: JSON.stringify({ url: 'https://hooks.example/x', events: ['finding.created'] }) })
    expect(made.status).toBe(201)
    const { endpoint, secret } = await made.json() as any
    expect(secret).toStartWith('whsec_')
    // Another account's key cannot see or delete it.
    const otherKey = store.newApiKey(store.findOrCreateUser('other@example.com').id)
    expect((await app.request(`/api/v1/webhooks/${endpoint.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${otherKey}` } })).status).toBe(404)
    expect((await app.request(`/api/v1/webhooks/${endpoint.id}`, { method: 'DELETE', headers: auth })).status).toBe(200)
  })
})
