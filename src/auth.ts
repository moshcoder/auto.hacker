/**
 * Who is asking: an emailed magic link (sign-up too: an unknown address makes the
 * account), a session cookie, or an account API key (ah_…) for the CLI, TUI and
 * MCP. Secrets are kept as SHA-256 only. The sign-in form never reveals whether an
 * address has an account. Passkeys are skipped: most visitors reach us through the
 * pit.world relay, and a passkey binds to one hostname.
 */
import { randomBytes } from 'node:crypto'
import { hashKey, type Store, type User } from './db.ts'

export const SESSION_COOKIE = 'ah_session'
const SESSION_DAYS = 90
const LINK_MINUTES = 20

export type Mail = { to: string; subject: string; text: string; html: string }
export type Mailer = (mail: Mail) => Promise<unknown>

export function resendMailer(apiKey: string, from: string, fetchImpl: typeof fetch = fetch): Mailer {
  return async ({ to, subject, text, html }) => {
    const res = await fetchImpl('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from, to: [to], subject, text, html }),
      signal: AbortSignal.timeout(15_000),
    })
    if (!res.ok) throw new Error(`mail provider answered ${res.status}: ${(await res.text()).slice(0, 200)}`)
  }
}

/** Without a mail key (local dev) the link goes to the log instead. */
export const consoleMailer: Mailer = async ({ to, text }) => console.log(`[mail] to ${to}\n${text}`)

export const validEmail = (value: unknown): string | null => {
  const email = String(value ?? '').trim().toLowerCase()
  return email.length <= 254 && /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[a-z0-9-]{2,}$/i.test(email) ? email : null
}

export const safeNext = (value: unknown): string | null => {
  const next = String(value ?? '')
  return next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') && next.length < 500 ? next : null
}

export class Auth {
  constructor(private store: Store, private mailer: Mailer, private now = () => Date.now()) {}

  async sendLink(emailInput: string, next: string | null, base: string): Promise<boolean> {
    const email = validEmail(emailInput)
    if (!email) return false
    const db = this.store.db
    const recent = (db.query('SELECT COUNT(*) AS n FROM magic_links WHERE email = ? AND created_at > ?').get(email, this.now() - 15 * 60_000) as { n: number }).n
    if (recent >= 5) return true
    const token = randomBytes(24).toString('base64url')
    db.query('INSERT INTO magic_links (token_hash, email, next, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run(hashKey(token), email, safeNext(next), this.now(), this.now() + LINK_MINUTES * 60_000)
    const url = `${base}/auth/verify?token=${token}`
    const text = `Sign in to auto.hacker:\n\n${url}\n\nThe link works once, for ${LINK_MINUTES} minutes. If you did not ask for it, ignore this email.`
    const html = `<p>Sign in to <strong>auto.hacker</strong>:</p><p><a href="${url}" style="display:inline-block;padding:10px 18px;background:#12e19a;color:#04140e;border-radius:8px;text-decoration:none;font-weight:700">Sign in</a></p><p style="color:#789;font-size:13px">Or open ${url}<br>The link works once, for ${LINK_MINUTES} minutes. If you did not ask for it, ignore this email.</p>`
    try { await this.mailer({ to: email, subject: 'Your auto.hacker sign-in link', text, html }) } catch (error) { console.error(`[auth] mail failed: ${(error as Error).message}`) }
    return true
  }

  consumeLink(token: string): { user: User; next: string | null; created: boolean } | null {
    const hash = hashKey(String(token))
    const db = this.store.db
    const row = db.query('SELECT email, next, expires_at FROM magic_links WHERE token_hash = ?').get(hash) as { email: string; next: string | null; expires_at: number } | null
    db.query('DELETE FROM magic_links WHERE token_hash = ? OR expires_at < ?').run(hash, this.now())
    if (!row || row.expires_at < this.now()) return null
    const created = !this.store.userByEmail(row.email)
    return { user: this.store.findOrCreateUser(row.email), next: row.next, created }
  }

  createSession(userId: string): string {
    const token = randomBytes(24).toString('base64url')
    this.store.db.query('INSERT INTO sessions (id_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(hashKey(token), userId, this.now(), this.now() + SESSION_DAYS * 86_400_000)
    return token
  }
  sessionUser(token: string | undefined | null): User | null {
    if (!token) return null
    const row = this.store.db.query('SELECT user_id, expires_at FROM sessions WHERE id_hash = ?').get(hashKey(token)) as { user_id: string; expires_at: number } | null
    if (!row || row.expires_at < this.now()) return null
    return this.store.user(row.user_id)
  }
  endSession(token: string | undefined | null): void { if (token) this.store.db.query('DELETE FROM sessions WHERE id_hash = ?').run(hashKey(token)) }
}
