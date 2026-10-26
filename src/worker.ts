/**
 * The run worker. Pulls queued runs, and this is the SECOND place the ownership
 * gate is enforced: immediately before the engine is called, the live proof is
 * checked again. A run whose proof has vanished since launch is refused here and
 * never reaches the engine.
 *
 * It also drives scheduled scans (due subscriptions) and emits every step and
 * finding on an in-process bus the SSE endpoint subscribes to, so a run streams
 * live. On completion it emails the owner a summary (Resend, via the injected mailer).
 */
import { checkOwnership } from './gate.ts'
import { runPentest, type Finding as EngineFinding } from './engine.ts'
import type { AutoHacker } from './service.ts'
import type { Run, Store } from './db.ts'
import type { Mailer } from './auth.ts'

export type RunEvent =
  | { type: 'status'; status: string; at: number }
  | { type: 'step'; note: string; at: number }
  | { type: 'finding'; finding: { type: string; severity: string; message: string; location: string }; at: number }
  | { type: 'done'; summary: string; counts: Record<string, number>; at: number }
  | { type: 'error'; error: string; at: number }
  | { type: 'refused'; error: string; at: number }

/** Per-run event fan-out with a backfill buffer, so a late SSE client still sees the whole run. */
export class RunBus {
  private subs = new Map<string, Set<(e: RunEvent) => void>>()
  private log = new Map<string, RunEvent[]>()
  emit(runId: string, e: RunEvent): void {
    const buf = this.log.get(runId) ?? []
    buf.push(e)
    if (buf.length > 500) buf.shift()
    this.log.set(runId, buf)
    for (const fn of this.subs.get(runId) ?? []) { try { fn(e) } catch { /* ignore */ } }
  }
  backfill(runId: string): RunEvent[] { return this.log.get(runId) ?? [] }
  subscribe(runId: string, fn: (e: RunEvent) => void): () => void {
    const set = this.subs.get(runId) ?? new Set()
    set.add(fn); this.subs.set(runId, set)
    return () => { set.delete(fn); if (!set.size) this.subs.delete(runId) }
  }
  done(runId: string): boolean { return (this.log.get(runId) ?? []).some((e) => e.type === 'done' || e.type === 'error' || e.type === 'refused') }
}

export class Worker {
  readonly bus = new RunBus()
  private running = false
  private timer: ReturnType<typeof setInterval> | null = null

  constructor(private store: Store, private service: AutoHacker, private mailer: Mailer | null, private origin: string) {}

  start(everyMs = 2000): void {
    if (this.timer) return
    const tick = () => void this.tick().catch((e) => console.error(`[worker] tick: ${(e as Error).message}`))
    this.timer = setInterval(tick, everyMs)
    this.timer.unref?.()
    tick()
  }
  stop(): void { if (this.timer) clearInterval(this.timer); this.timer = null }

  private async tick(): Promise<void> {
    if (this.running) return
    this.running = true
    try {
      await this.sweepSchedules()
      for (const run of this.store.queuedRuns()) await this.execute(run)
    } finally { this.running = false }
  }

  /** Create due scheduled runs (createRun re-checks the gate), execute, email, advance. */
  private async sweepSchedules(): Promise<void> {
    for (const s of this.store.dueSchedules()) {
      const target = this.store.target(s.targetId)
      const user = this.store.user(s.userId)
      // Advance first so a persistent failure does not hot-loop.
      this.store.advanceSchedule(s.targetId, Date.now() + this.service.cadenceMs(s.cadence), s.lastRunId ?? '')
      if (!target || !user) continue
      try {
        const run = await this.service.createRun(user, target, `scheduled:${s.cadence}`)
        this.store.advanceSchedule(s.targetId, Date.now() + this.service.cadenceMs(s.cadence), run.id)
      } catch (e) {
        console.error(`[worker] scheduled run for ${s.host} refused/failed: ${(e as Error).message}`)
      }
    }
  }

  async execute(run: Run): Promise<void> {
    const target = this.store.target(run.targetId)
    const user = this.store.user(run.userId)
    if (!target || !user) { this.store.setRunStatus(run.id, 'error', { error: 'target or user gone' }); return }

    this.store.setRunStatus(run.id, 'running')
    this.bus.emit(run.id, { type: 'status', status: 'running', at: Date.now() })

    // === SECOND GATE WALL: re-check the live proof right before the engine ===
    const token = this.service.token(user, target.host)
    const gate = await checkOwnership({ host: target.host, token }, this.service.config.gate)
    if (!gate.ok) {
      const error = `Ownership of ${target.host} is no longer proven — refused before scanning. Looked: ${gate.looked.join('; ')}`
      this.store.setRunStatus(run.id, 'refused', { summary: 'Refused: ownership lapsed.', error })
      this.store.recordCheckFail(target.id)
      this.bus.emit(run.id, { type: 'refused', error, at: Date.now() })
      return
    }
    if (gate.method) this.store.recordVerified(target, gate.method, token, user.email)

    try {
      const onStep = (note: string) => this.bus.emit(run.id, { type: 'step', note, at: Date.now() })
      const result = await runPentest(target.host, onStep)
      for (const f of result.findings as EngineFinding[]) {
        this.store.addFinding(run.id, { type: f.type, severity: f.severity, message: f.message, location: f.location, details: f.details ?? null })
        this.bus.emit(run.id, { type: 'finding', finding: { type: f.type, severity: f.severity, message: f.message, location: f.location }, at: Date.now() })
      }
      this.store.setRunStatus(run.id, 'done', { summary: result.summary, counts: result.severity_summary })
      this.bus.emit(run.id, { type: 'done', summary: result.summary, counts: result.severity_summary, at: Date.now() })
      await this.emailResult(user.email, this.store.run(run.id)!)
    } catch (e) {
      const error = (e as Error).message
      this.store.setRunStatus(run.id, 'error', { error })
      this.bus.emit(run.id, { type: 'error', error, at: Date.now() })
    }
  }

  private async emailResult(to: string, run: Run): Promise<void> {
    if (!this.mailer) return
    const c = run.counts ?? {}
    const link = `${this.origin}/runs/${run.id}`
    const line = `${c.critical ?? 0} critical · ${c.high ?? 0} high · ${c.medium ?? 0} medium · ${c.low ?? 0} low`
    const text = `Your auto.hacker scan of ${run.host} finished.\n\n${run.summary}\n${line}\n\nFull report: ${link}\n\nThis was an authorized, non-destructive scan of a property you verified. It is not a substitute for a manual pentest.`
    const html = `<p>Your <strong>auto.hacker</strong> scan of <strong>${run.host}</strong> finished.</p><p>${run.summary}<br><code>${line}</code></p><p><a href="${link}" style="display:inline-block;padding:10px 18px;background:#12e19a;color:#04140e;border-radius:8px;text-decoration:none;font-weight:700">Open the report</a></p><p style="color:#789;font-size:13px">Authorized, non-destructive scan of a property you verified. Not a substitute for a manual pentest.</p>`
    try { await this.mailer({ to, subject: `auto.hacker: scan of ${run.host} finished (${line})`, text, html }) } catch (e) { console.error(`[worker] result mail failed: ${(e as Error).message}`) }
  }
}
