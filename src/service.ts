/**
 * auto.hacker's rules. Everything a run passes through is here, and the ownership
 * gate is enforced in TWO places that both call checkOwnership against the live
 * proof:
 *
 *   createRun()  — at launch, server-side. No live proof => the run is REFUSED and
 *                  never queued. This is the first wall.
 *   (worker.ts)  — again, immediately before the engine call. The second wall.
 *
 * A target the user cannot prove they own can never reach the engine.
 */
import { checkOwnership, normalizeHost, proofInstructions, verifyToken, type GateDeps, type Method, OwnershipError } from './gate.ts'
import type { Run, Store, Target, User } from './db.ts'
import { createHmac, timingSafeEqual } from 'node:crypto'
import { Webhooks, sqliteStore as webhookStore, type GuardOptions } from '@profullstack/webhooks'

/**
 * What auto.hacker tells customer webhooks about. Finding payloads carry the
 * severity and the check's title only: never the probe payload, the probed URL or
 * the raw details (those stay behind the authenticated report).
 */
export const WEBHOOK_EVENTS = ['target.verified', 'run.started', 'run.completed', 'run.failed', 'run.refused', 'finding.created']

export class InputError extends Error { constructor(message: string, readonly field?: string) { super(message) } }

export type CoinPayConfig = { baseUrl: string; apiKey: string; businessId: string; webhookSecret: string }
export type Config = {
  origin: string
  secret: string
  coinpay: CoinPayConfig | null
  priceUsd: number
  /** at most one run per host per this many ms */
  runCooldownMs: number
  gate?: GateDeps
  /** Checks on customer webhook URLs; tests allow private addresses. */
  webhookGuard?: GuardOptions
  /** fetch for webhook deliveries (tests inject a receiver). */
  webhookFetch?: typeof fetch
}

const SETTLED = new Set(['paid', 'completed', 'confirmed', 'forwarded', 'succeeded', 'settled'])
const CADENCE_MS: Record<string, number> = { daily: 86_400_000, weekly: 7 * 86_400_000, monthly: 30 * 86_400_000 }

export class AutoHacker {
  /** Customer webhooks (@profullstack/webhooks): endpoints per account, durable delivery. */
  readonly hooks: Webhooks

  constructor(readonly store: Store, readonly config: Config) {
    this.hooks = new Webhooks({
      store: webhookStore(store.db as never),
      source: config.origin,
      eventTypes: WEBHOOK_EVENTS,
      ...(config.webhookFetch ? { fetchImpl: config.webhookFetch } : {}),
      ...(config.webhookGuard ? { guard: config.webhookGuard } : {}),
      log: (m) => console.log(m),
    })
  }

  /** Tell the account's webhooks; never in the way of a scan. */
  hook(userId: string, type: string, data: Record<string, unknown>, subject: string): void {
    void this.hooks.emit(userId, type, data, { subject }).catch((e) => console.error(`[webhooks] ${type}: ${(e as Error).message}`))
  }

  /** Record a live proof; fires target.verified when the host was not verified before. */
  markVerified(user: User, target: Target, method: Method, token: string): void {
    const was = this.store.target(target.id)?.state
    this.store.recordVerified(target, method, token, user.email)
    if (was !== 'verified') this.hook(user.id, 'target.verified', { target_id: target.id, host: target.host, method }, `target:${target.id}`)
  }

  /** run.refused: the gate turned a run away (at launch or right before the engine). */
  hookRefused(run: Run, reason: string): void {
    this.hook(run.userId, 'run.refused', { run_id: run.id, target_id: run.targetId, host: run.host, trigger: run.trigger, reason, url: `${this.config.origin}/runs/${run.id}` }, `run:${run.id}`)
  }

  /** The exact proof value this user must publish for this host. */
  token(user: User, host: string): string { return verifyToken(this.config.secret, user.id, host) }

  proof(user: User, host: string) { return proofInstructions(host, this.token(user, host)) }

  addTarget(user: User, hostInput: string): Target {
    const host = normalizeHost(hostInput)
    if (!host) throw new InputError('Enter a public hostname you own, e.g. example.com (no IPs or internal names).', 'host')
    return this.store.addTarget(user.id, host)
  }

  listTargets(user: User): Target[] { return this.store.targetsOf(user.id) }

  /** Re-check the live proof now. On success: record it + append the consent log. On failure: bump the lapse counter. */
  async verify(user: User, target: Target, only?: Method): Promise<{ ok: boolean; method?: Method; looked: string[] }> {
    if (target.userId !== user.id) throw new InputError('Not your target.')
    const token = this.token(user, target.host)
    const r = await checkOwnership({ host: target.host, token, only }, this.config.gate)
    if (r.ok && r.method) this.markVerified(user, target, r.method, token)
    else this.store.recordCheckFail(target.id)
    return r
  }

  /**
   * THE GATE at launch. Re-checks the live proof before anything is queued.
   * No proof => a 'refused' run is written (for the audit trail and the UI) and
   * an InputError is thrown. With proof => a 'queued' run the worker will pick up.
   */
  async createRun(user: User, target: Target, trigger = 'manual'): Promise<Run> {
    if (target.userId !== user.id) throw new InputError('Not your target.')
    const recent = this.store.runsForTarget(target.id, 1)[0]
    if (recent && Date.now() - recent.createdAt < this.config.runCooldownMs && (recent.status === 'queued' || recent.status === 'running')) {
      throw new InputError('A scan for this host is already in flight. Give it a minute.')
    }
    if (recent && Date.now() - recent.createdAt < this.config.runCooldownMs) {
      throw new InputError('That host was scanned very recently. One scan per host every few minutes.')
    }
    const token = this.token(user, target.host)
    const gate = await checkOwnership({ host: target.host, token }, this.config.gate)
    if (!gate.ok) {
      const run = this.store.createRun(target, trigger, 'refused')
      this.store.setRunStatus(run.id, 'refused', { summary: 'Refused: ownership of this host is not proven.', error: `No live proof found. Looked: ${gate.looked.join('; ')}` })
      this.store.recordCheckFail(target.id)
      this.hookRefused(run, 'ownership is not proven')
      throw new OwnershipError(`auto.hacker will not scan ${target.host}: ownership is not proven. Add the DNS TXT, /.well-known file, or meta tag shown on the target page, then Verify.`)
    }
    // Record the fresh proof (keeps verified state + audit log current) and queue.
    if (gate.method) this.markVerified(user, target, gate.method, token)
    return this.store.createRun(target, trigger, 'queued')
  }

  // --- scheduled scans ---
  subscribe(user: User, target: Target, cadence = 'weekly'): Target {
    if (target.userId !== user.id) throw new InputError('Not your target.')
    if (!CADENCE_MS[cadence]) throw new InputError('Cadence must be daily, weekly or monthly.', 'cadence')
    if (target.state !== 'verified') throw new InputError('Verify the host before subscribing it to scheduled scans.')
    this.store.upsertSchedule(target, cadence, Date.now() + CADENCE_MS[cadence])
    return target
  }
  unsubscribe(user: User, target: Target): void {
    if (target.userId !== user.id) throw new InputError('Not your target.')
    this.store.deactivateSchedule(target.id)
  }
  cadenceMs(cadence: string): number { return CADENCE_MS[cadence] ?? CADENCE_MS.weekly }

  // --- CoinPay (paid tier = scheduled scans) ---
  async checkout(user: User, days = 30, fetcher: typeof fetch = fetch): Promise<{ url: string; sessionId: string }> {
    const cp = this.config.coinpay
    if (!cp) throw new InputError('Payment is not set up on this server yet.')
    const res = await fetcher(`${cp.baseUrl}/api/checkout/sessions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${cp.apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ business_id: cp.businessId, amount: this.config.priceUsd, currency: 'USD', customer_email: user.email, account_id: user.id, property: 'auto.hacker.pit.world', description: `auto.hacker scheduled scans, ${days} days`, metadata: { product: 'scheduled', days, user: user.id }, success_url: `${this.config.origin}/account?paid=1`, cancel_url: `${this.config.origin}/account` }),
      signal: AbortSignal.timeout(20_000),
    })
    if (!res.ok) throw new Error(`CoinPay said ${res.status}: ${(await res.text()).slice(0, 200)}`)
    const body = (await res.json()) as any
    const session = body?.session ?? body
    const url = String(session?.url ?? session?.checkout_url ?? '')
    const sessionId = String(session?.id ?? session?.checkout_session_id ?? '')
    if (!url) throw new Error('CoinPay returned no checkout URL')
    return { url, sessionId }
  }

  /** CoinPay webhook: header `t=<unix>,v1=<hmac of "t.body">`. We only acknowledge; funding state is informational here. */
  webhook(raw: string, header: string | undefined, nowMs = Date.now()): { ok: boolean; status?: number; event?: string } {
    const cp = this.config.coinpay
    if (!cp?.webhookSecret || !header) return { ok: false, status: 401 }
    const parts = Object.fromEntries(header.split(',').map((kv) => kv.split('=').map((s) => s.trim())))
    const t = Number(parts.t)
    if (!Number.isFinite(t) || !parts.v1 || Math.abs(nowMs / 1000 - t) > 300) return { ok: false, status: 401 }
    const expected = Buffer.from(createHmac('sha256', cp.webhookSecret).update(`${parts.t}.${raw}`).digest('hex'), 'hex')
    const given = Buffer.from(String(parts.v1), 'hex')
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) return { ok: false, status: 401 }
    let payload: any
    try { payload = JSON.parse(raw) } catch { return { ok: false, status: 400 } }
    const status = String(payload?.data?.status ?? payload?.type ?? '').toLowerCase()
    return { ok: true, event: SETTLED.has(status.replace(/^payment\./, '')) ? 'settled' : status }
  }

  exportFindings(run: Run, fmt: 'json' | 'csv'): { body: string; type: string } {
    const fs = this.store.findings(run.id)
    if (fmt === 'json') return { body: JSON.stringify({ run: { id: run.id, host: run.host, status: run.status, summary: run.summary, counts: run.counts, finishedAt: run.finishedAt }, findings: fs }, null, 2), type: 'application/json' }
    const esc = (s: string) => `"${String(s ?? '').replace(/"/g, '""')}"`
    const rows = [['severity', 'type', 'message', 'location'].join(',')]
    for (const f of fs) rows.push([f.severity, f.type, f.message, f.location].map(esc).join(','))
    return { body: rows.join('\n') + '\n', type: 'text/csv' }
  }
}
