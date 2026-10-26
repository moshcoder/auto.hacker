/**
 * auto.hacker's state: one SQLite file.
 *
 * An account is an email address (magic link, auth.ts). A target is a host an
 * account wants scanned; it carries at most one live verification and an
 * append-only consent/authorization log. A run is one scan of a verified host,
 * holding its findings. A schedule subscribes a target to periodic scans.
 *
 * Verification is the gate's bookkeeping, never its authority: a row here says a
 * proof was seen, but every run re-checks the live proof (src/gate.ts) before the
 * engine is called. consent_log is immutable (append only) and is the audit trail.
 */
import { Database } from 'bun:sqlite'
import { createHash, randomBytes } from 'node:crypto'

export const hashKey = (key: string) => createHash('sha256').update(key).digest('hex')
export const newId = (bytes = 9) => randomBytes(bytes).toString('base64url')

export type User = { id: string; email: string; createdAt: number; displayName: string | null }
export type Method = 'dns' | 'file' | 'meta'
export type VerifyState = 'unverified' | 'verified' | 'lapsed'
export type RunStatus = 'queued' | 'running' | 'done' | 'error' | 'refused'

export type Target = {
  id: string
  userId: string
  host: string
  createdAt: number
  method: Method | null
  verifiedAt: number | null
  lastOkAt: number | null
  lastCheckAt: number | null
  failCount: number
  state: VerifyState
}

export type Run = {
  id: string
  targetId: string
  userId: string
  host: string
  status: RunStatus
  trigger: string
  summary: string | null
  counts: Record<string, number> | null
  error: string | null
  createdAt: number
  startedAt: number | null
  finishedAt: number | null
}

export type Finding = { id: string; runId: string; type: string; severity: string; message: string; location: string; details: string | null; createdAt: number }
export type Schedule = { targetId: string; userId: string; host: string; cadence: string; active: boolean; nextAt: number; lastRunId: string | null; createdAt: number }

export class Store {
  readonly db: Database
  constructor(path: string, readonly secret: string) {
    if (!secret || secret.length < 16) throw new Error('AUTOHACKER_KEY must be set (32 random bytes)')
    this.db = new Database(path, { create: true })
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, display_name TEXT, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS magic_links (token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, next TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS magic_links_email ON magic_links(email, created_at);
      CREATE TABLE IF NOT EXISTS api_keys (key_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL);

      CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        host TEXT NOT NULL,
        method TEXT,
        verified_at INTEGER,
        last_ok_at INTEGER,
        last_check_at INTEGER,
        fail_count INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT 'unverified',
        created_at INTEGER NOT NULL,
        UNIQUE (user_id, host)
      );
      CREATE INDEX IF NOT EXISTS targets_user ON targets(user_id, created_at DESC);

      -- Immutable authorization log: one row per successful verification. Never updated or deleted.
      CREATE TABLE IF NOT EXISTS consent_log (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        token TEXT NOT NULL,
        at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS consent_host ON consent_log(host, at DESC);

      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        host TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        trigger TEXT NOT NULL DEFAULT 'manual',
        summary TEXT,
        counts TEXT,
        error TEXT,
        created_at INTEGER NOT NULL,
        started_at INTEGER,
        finished_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS runs_user ON runs(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS runs_target ON runs(target_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS runs_status ON runs(status);

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        location TEXT NOT NULL,
        details TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS findings_run ON findings(run_id);

      CREATE TABLE IF NOT EXISTS schedules (
        target_id TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        host TEXT NOT NULL,
        cadence TEXT NOT NULL DEFAULT 'weekly',
        active INTEGER NOT NULL DEFAULT 1,
        next_at INTEGER NOT NULL,
        last_run_id TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS schedules_due ON schedules(active, next_at);
    `)
  }

  // --- accounts (secrets stored as SHA-256 only) ---
  findOrCreateUser(email: string, now = Date.now()): User {
    this.db.query('INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?, ?, ?)').run(newId(), email.toLowerCase(), now)
    return this.userByEmail(email)!
  }
  private toUser(r: any): User | null { return r ? { id: r.id, email: r.email, createdAt: r.created_at, displayName: r.display_name ?? null } : null }
  user(id: string): User | null { return this.toUser(this.db.query('SELECT * FROM users WHERE id = ?').get(id)) }
  userByEmail(email: string): User | null { return this.toUser(this.db.query('SELECT * FROM users WHERE email = ?').get(email.toLowerCase())) }
  setDisplayName(userId: string, name: string | null): void { this.db.query('UPDATE users SET display_name = ? WHERE id = ?').run(name, userId) }

  newApiKey(userId: string, now = Date.now()): string {
    const key = `ah_${randomBytes(24).toString('base64url')}`
    this.db.query('DELETE FROM api_keys WHERE user_id = ?').run(userId)
    this.db.query('INSERT INTO api_keys (key_hash, user_id, created_at) VALUES (?, ?, ?)').run(hashKey(key), userId, now)
    return key
  }
  byApiKey(key: string): User | null {
    if (!key.startsWith('ah_')) return null
    const r: any = this.db.query('SELECT user_id FROM api_keys WHERE key_hash = ?').get(hashKey(key))
    return r ? this.user(r.user_id) : null
  }

  // --- targets ---
  private toTarget(r: any): Target | null {
    return r ? { id: r.id, userId: r.user_id, host: r.host, createdAt: r.created_at, method: r.method, verifiedAt: r.verified_at, lastOkAt: r.last_ok_at, lastCheckAt: r.last_check_at, failCount: r.fail_count, state: r.state } : null
  }
  addTarget(userId: string, host: string, now = Date.now()): Target {
    this.db.query('INSERT OR IGNORE INTO targets (id, user_id, host, created_at) VALUES (?, ?, ?, ?)').run(newId(), userId, host, now)
    return this.targetByHost(userId, host)!
  }
  target(id: string): Target | null { return this.toTarget(this.db.query('SELECT * FROM targets WHERE id = ?').get(id)) }
  targetByHost(userId: string, host: string): Target | null { return this.toTarget(this.db.query('SELECT * FROM targets WHERE user_id = ? AND host = ?').get(userId, host)) }
  targetsOf(userId: string): Target[] { return (this.db.query('SELECT * FROM targets WHERE user_id = ? ORDER BY created_at DESC').all(userId) as any[]).map((r) => this.toTarget(r)!) }
  removeTarget(id: string): void { this.db.query('DELETE FROM targets WHERE id = ?').run(id) }

  /** Record a successful verification: update target state AND append an immutable consent_log row. */
  recordVerified(t: Target, method: Method, token: string, email: string, now = Date.now()): void {
    this.db.transaction(() => {
      this.db.query("UPDATE targets SET method = ?, verified_at = COALESCE(verified_at, ?), last_ok_at = ?, last_check_at = ?, fail_count = 0, state = 'verified' WHERE id = ?").run(method, now, now, now, t.id)
      this.db.query('INSERT INTO consent_log (id, user_id, email, host, method, token, at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(newId(), t.userId, email, t.host, method, token, now)
    })()
  }
  /** A failed re-check: bump the counter, mark lapsed after `maxFail` strikes. */
  recordCheckFail(id: string, maxFail = 3, now = Date.now()): void {
    this.db.query("UPDATE targets SET last_check_at = ?, fail_count = fail_count + 1, state = CASE WHEN fail_count + 1 >= ? THEN 'lapsed' ELSE state END WHERE id = ?").run(now, maxFail, id)
  }
  consentFor(host: string, limit = 50): any[] { return this.db.query('SELECT user_id, email, host, method, at FROM consent_log WHERE host = ? ORDER BY at DESC LIMIT ?').all(host, limit) as any[] }

  // --- runs + findings ---
  private toRun(r: any): Run | null {
    return r ? { id: r.id, targetId: r.target_id, userId: r.user_id, host: r.host, status: r.status, trigger: r.trigger, summary: r.summary, counts: r.counts ? JSON.parse(r.counts) : null, error: r.error, createdAt: r.created_at, startedAt: r.started_at, finishedAt: r.finished_at } : null
  }
  createRun(t: Target, trigger: string, status: RunStatus = 'queued', now = Date.now()): Run {
    const id = newId()
    this.db.query('INSERT INTO runs (id, target_id, user_id, host, status, trigger, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, t.id, t.userId, t.host, status, trigger, now)
    return this.run(id)!
  }
  run(id: string): Run | null { return this.toRun(this.db.query('SELECT * FROM runs WHERE id = ?').get(id)) }
  runsOf(userId: string, limit = 50): Run[] { return (this.db.query('SELECT * FROM runs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(userId, limit) as any[]).map((r) => this.toRun(r)!) }
  runsForTarget(targetId: string, limit = 50): Run[] { return (this.db.query('SELECT * FROM runs WHERE target_id = ? ORDER BY created_at DESC LIMIT ?').all(targetId, limit) as any[]).map((r) => this.toRun(r)!) }
  queuedRuns(): Run[] { return (this.db.query("SELECT * FROM runs WHERE status = 'queued' ORDER BY created_at").all() as any[]).map((r) => this.toRun(r)!) }
  setRunStatus(id: string, status: RunStatus, patch: { summary?: string; counts?: Record<string, number>; error?: string } = {}, now = Date.now()): void {
    const sets = ['status = ?']; const vals: any[] = [status]
    if (status === 'running') { sets.push('started_at = COALESCE(started_at, ?)'); vals.push(now) }
    if (status === 'done' || status === 'error' || status === 'refused') { sets.push('finished_at = ?'); vals.push(now) }
    if (patch.summary !== undefined) { sets.push('summary = ?'); vals.push(patch.summary) }
    if (patch.counts !== undefined) { sets.push('counts = ?'); vals.push(JSON.stringify(patch.counts)) }
    if (patch.error !== undefined) { sets.push('error = ?'); vals.push(patch.error) }
    vals.push(id)
    this.db.query(`UPDATE runs SET ${sets.join(', ')} WHERE id = ?`).run(...vals)
  }
  addFinding(runId: string, f: { type: string; severity: string; message: string; location: string; details?: string | null }, now = Date.now()): Finding {
    const id = newId()
    this.db.query('INSERT INTO findings (id, run_id, type, severity, message, location, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, runId, f.type, f.severity, f.message, f.location, f.details ?? null, now)
    return this.db.query('SELECT * FROM findings WHERE id = ?').get(id) as Finding
  }
  findings(runId: string): Finding[] { return this.db.query('SELECT * FROM findings WHERE run_id = ? ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END').all(runId) as Finding[] }

  // --- schedules ---
  private toSchedule(r: any): Schedule | null { return r ? { targetId: r.target_id, userId: r.user_id, host: r.host, cadence: r.cadence, active: !!r.active, nextAt: r.next_at, lastRunId: r.last_run_id, createdAt: r.created_at } : null }
  upsertSchedule(t: Target, cadence: string, nextAt: number, now = Date.now()): Schedule {
    this.db.query('INSERT INTO schedules (target_id, user_id, host, cadence, active, next_at, created_at) VALUES (?, ?, ?, ?, 1, ?, ?) ON CONFLICT(target_id) DO UPDATE SET cadence = excluded.cadence, active = 1, next_at = excluded.next_at').run(t.id, t.userId, t.host, cadence, nextAt, now)
    return this.schedule(t.id)!
  }
  schedule(targetId: string): Schedule | null { return this.toSchedule(this.db.query('SELECT * FROM schedules WHERE target_id = ?').get(targetId)) }
  schedulesOf(userId: string): Schedule[] { return (this.db.query('SELECT * FROM schedules WHERE user_id = ? ORDER BY created_at DESC').all(userId) as any[]).map((r) => this.toSchedule(r)!) }
  deactivateSchedule(targetId: string): void { this.db.query('UPDATE schedules SET active = 0 WHERE target_id = ?').run(targetId) }
  dueSchedules(now = Date.now()): Schedule[] { return (this.db.query('SELECT * FROM schedules WHERE active = 1 AND next_at <= ?').all(now) as any[]).map((r) => this.toSchedule(r)!) }
  advanceSchedule(targetId: string, nextAt: number, lastRunId: string): void { this.db.query('UPDATE schedules SET next_at = ?, last_run_id = ? WHERE target_id = ?').run(nextAt, lastRunId, targetId) }

  stats(): { users: number; targets: number; verified: number; runs: number; findings: number } {
    return this.db.query("SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM targets) AS targets, (SELECT COUNT(*) FROM targets WHERE state = 'verified') AS verified, (SELECT COUNT(*) FROM runs WHERE status = 'done') AS runs, (SELECT COUNT(*) FROM findings) AS findings").get() as any
  }
}
