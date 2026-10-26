import { expect, test, describe, beforeEach } from 'bun:test'
import { Store } from '../src/db.ts'
import { AutoHacker, InputError } from '../src/service.ts'
import { OwnershipError } from '../src/gate.ts'
import { Worker } from '../src/worker.ts'
import type { GateDeps } from '../src/gate.ts'

const SECRET = 'y'.repeat(32)
const HOST = 'mysite.example'

// A gate whose DNS answer we flip at will, so we can prove refusal at each wall.
let proofOn = true
let proofToken = ''
const gate: GateDeps = {
  resolveTxt: async () => (proofOn && proofToken ? [[`autohacker-verify=${proofToken}`]] : []),
  fetchText: async () => null,
}

function fresh() {
  const store = new Store(':memory:', SECRET)
  const service = new AutoHacker(store, { origin: 'https://auto.hacker.pit.world', secret: SECRET, coinpay: null, priceUsd: 9, runCooldownMs: 0, gate })
  const user = store.findOrCreateUser('owner@example.com')
  const target = service.addTarget(user, HOST)
  proofToken = service.token(user, HOST)
  return { store, service, user, target }
}

beforeEach(() => { proofOn = true })

describe('wall 1 — createRun', () => {
  test('REFUSES a target with no live proof: throws, writes a refused run, queues nothing', async () => {
    const { store, service, user, target } = fresh()
    proofOn = false
    await expect(service.createRun(user, target)).rejects.toBeInstanceOf(OwnershipError)
    expect(store.queuedRuns().length).toBe(0)
    const runs = store.runsForTarget(target.id)
    expect(runs.length).toBe(1)
    expect(runs[0]!.status).toBe('refused')
  })

  test('queues a run when the proof is live, and records the consent log', async () => {
    const { store, service, user, target } = fresh()
    const run = await service.createRun(user, target)
    expect(run.status).toBe('queued')
    expect(store.queuedRuns().length).toBe(1)
    expect(store.consentFor(HOST).length).toBe(1)
    expect(store.target(target.id)!.state).toBe('verified')
  })
})

describe('wall 2 — worker.execute re-checks before the engine', () => {
  test('a run whose proof vanished after queueing is REFUSED, engine never runs', async () => {
    const { store, service, user, target } = fresh()
    const run = await service.createRun(user, target)   // queued with proof
    proofOn = false                                      // proof removed before the worker runs
    const worker = new Worker(store, service, null, 'https://auto.hacker.pit.world')
    await worker.execute(run)
    const after = store.run(run.id)!
    expect(after.status).toBe('refused')
    expect(store.findings(run.id).length).toBe(0)       // engine produced nothing
    expect(worker.bus.backfill(run.id).some((e) => e.type === 'refused')).toBe(true)
  })

  test('a verified run runs the engine, persists findings, emits done, emails the owner', async () => {
    const { store, service, user, target } = fresh()
    // Stub the network the ENGINE uses (gate uses injected deps, not global fetch).
    const realFetch = globalThis.fetch
    globalThis.fetch = (async () => new Response('<html>ok</html>', { status: 200, headers: {} })) as unknown as typeof fetch
    let emailed = ''
    const worker = new Worker(store, service, async (m) => { emailed = m.subject }, 'https://auto.hacker.pit.world')
    try {
      const run = await service.createRun(user, target)
      await worker.execute(run)
      const after = store.run(run.id)!
      expect(after.status).toBe('done')
      expect(store.findings(run.id).length).toBeGreaterThan(0)   // missing headers / no CSP on a bare 200
      const ev = worker.bus.backfill(run.id)
      expect(ev.some((e) => e.type === 'done')).toBe(true)
      expect(ev.some((e) => e.type === 'finding')).toBe(true)
      expect(emailed).toContain('auto.hacker: scan of mysite.example')
    } finally { globalThis.fetch = realFetch }
  })
})

describe('other rules', () => {
  test('addTarget rejects IPs and internal names', () => {
    const { service, user } = fresh()
    expect(() => service.addTarget(user, '10.0.0.1')).toThrow(InputError)
    expect(() => service.addTarget(user, 'router.local')).toThrow(InputError)
  })
  test('subscribe refuses an unverified host', () => {
    const { store, service, user } = fresh()
    const t = service.addTarget(user, 'notyet.example')
    expect(() => service.subscribe(user, store.target(t.id)!)).toThrow(/Verify the host/)
  })
})
