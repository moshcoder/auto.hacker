/**
 * The ownership gate — the one rule that lets this product exist.
 *
 * auto.hacker only ever scans a host the signed-in user has PROVEN they control.
 * Proof is a per-user-per-host token, `tok = HMAC(secret, "<user_id>:<host>")`,
 * placed by one of three methods the user picks:
 *
 *   dns   TXT  `_autohacker.<host>`                      = "autohacker-verify=<tok>"
 *   file  GET  `https://<host>/.well-known/autohacker-<tok>.txt`  body contains <tok>
 *   meta  GET  `https://<host>/`  <meta name="autohacker-verify" content="<tok>">
 *
 * Nothing here is advisory. `checkOwnership` is the only way a host becomes
 * verified, it is re-run server-side at run-launch AND again in the worker right
 * before the engine call, and a host with no live proof is REFUSED. The token is
 * derived, never stored, so a record placed yesterday still proves ownership today.
 *
 * DNS note ([[built-indie-app]]): Bun 1.4's node:dns Resolver given two servers
 * answers ENOTFOUND for a TXT each of them serves alone. So: one Resolver per
 * server, answers merged; and a fresh Resolver per lookup, because a long-lived
 * one caches NXDOMAIN for the zone's SOA minimum and keeps refusing a record the
 * user only just added.
 */
import { createHmac, timingSafeEqual } from 'node:crypto'
import { Resolver } from 'node:dns/promises'
import { isIP } from 'node:net'

export type Method = 'dns' | 'file' | 'meta'
export const METHODS: Method[] = ['dns', 'file', 'meta']
export const DNS_LABEL = '_autohacker'
export const DNS_PREFIX = 'autohacker-verify='
export const META_NAME = 'autohacker-verify'

export class OwnershipError extends Error {}

/** A bare hostname: lowercase, no scheme, no path, no port, no userinfo. null when it is not one we will ever touch. */
export function normalizeHost(input: unknown): string | null {
  let s = String(input ?? '').trim().toLowerCase()
  if (!s) return null
  if (s.includes('://')) {
    try { s = new URL(s).hostname } catch { return null }
  } else {
    s = s.replace(/^[^@]*@/, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '')
  }
  s = s.replace(/\.$/, '')
  if (s.length < 3 || s.length > 253) return null
  // A public, DNS-resolvable host only: no IP literals, no localhost, no internal names.
  if (isIP(s)) return null
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(s)) return null
  if (s === 'localhost' || s.endsWith('.localhost') || s.endsWith('.local') || s.endsWith('.internal')) return null
  return s
}

/** Reject hosts that resolve into private / loopback / link-local space before we ever fetch them (SSRF guard). */
export function privateIp(ip: string): boolean {
  if (/^(0\.|10\.|127\.|169\.254\.|192\.168\.)/.test(ip)) return true
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true
  if (/^(::1?$|::ffff:|fc|fd|fe80:)/i.test(ip)) return true
  return false
}

/** The exact TXT value the user must publish for this host. */
export function verifyToken(secret: string, userId: string, host: string): string {
  if (!secret || secret.length < 16) throw new OwnershipError('server misconfigured: AUTOHACKER_KEY unset')
  const h = normalizeHost(host)
  if (!h) throw new OwnershipError('not a scannable host')
  return createHmac('sha256', secret).update(`${userId}:${h}`).digest('base64url').slice(0, 32)
}

/** Constant-time compare of two short tokens. */
function tokenEq(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}

const publicDns = () =>
  ['1.1.1.1', '9.9.9.9'].map((server) => {
    const r = new Resolver({ timeout: 4000, tries: 2 })
    r.setServers([server])
    return r
  })

/** TXT records as the public resolvers see them, every answer merged. */
export async function publicTxt(name: string, resolvers: Pick<Resolver, 'resolveTxt'>[] = publicDns()): Promise<string[][]> {
  const answers = await Promise.all(resolvers.map((r) => r.resolveTxt(name).catch(() => [] as string[][])))
  return answers.flat()
}

export type GateDeps = {
  /** TXT lookups; tests inject their own. */
  resolveTxt?: (name: string) => Promise<string[][]>
  /** HTTP GET of a proof URL; returns the body text, or null if it will not load. Tests inject their own. */
  fetchText?: (url: string) => Promise<string | null>
}

/** A guarded GET: public host only, https, no redirects off-host, 5 s, small body. */
export async function fetchProof(url: string): Promise<string | null> {
  let u: URL
  try { u = new URL(url) } catch { return null }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
  const host = normalizeHost(u.hostname)
  if (!host) return null
  // Resolve and refuse private space (defence in depth; the host was already normalized to a public name).
  try {
    const r = new Resolver({ timeout: 4000, tries: 2 })
    const addrs = await r.resolve(host).catch(() => [] as string[])
    if (addrs.length && addrs.every((a) => privateIp(a))) return null
  } catch { /* resolution optional; normalizeHost already blocks literals */ }
  try {
    const res = await fetch(u, {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
      headers: { 'user-agent': 'auto.hacker-verify/1.0 (+https://auto.hacker.pit.world)' },
    })
    if (res.status >= 300) return null
    const reader = res.body?.getReader()
    if (!reader) return (await res.text()).slice(0, 262_144)
    let out = ''
    const dec = new TextDecoder()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      out += dec.decode(value, { stream: true })
      if (out.length > 262_144) { await reader.cancel(); break }
    }
    return out.slice(0, 262_144)
  } catch {
    return null
  }
}

export type OwnershipResult = { ok: boolean; method?: Method; looked: string[] }

/**
 * The gate. Returns ok only when a live proof for THIS user and THIS host is found
 * by one of the allowed methods. `only` narrows to the method the user chose.
 */
export async function checkOwnership(
  args: { host: string; token: string; only?: Method },
  deps: GateDeps = {},
): Promise<OwnershipResult> {
  const host = normalizeHost(args.host)
  if (!host) return { ok: false, looked: [] }
  const token = String(args.token ?? '')
  if (!token) return { ok: false, looked: [] }
  const methods = args.only ? [args.only] : METHODS
  const lookup = deps.resolveTxt ?? publicTxt
  const get = deps.fetchText ?? fetchProof
  const looked: string[] = []

  if (methods.includes('dns')) {
    const name = `${DNS_LABEL}.${host}`
    looked.push(`TXT ${name}`)
    const records = await lookup(name).catch(() => [] as string[][])
    const want = `${DNS_PREFIX}${token}`
    if (records.some((chunks) => chunks.join('').trim() === want)) return { ok: true, method: 'dns', looked }
  }
  if (methods.includes('file')) {
    const url = `https://${host}/.well-known/autohacker-${token}.txt`
    looked.push(`GET ${url}`)
    const body = await get(url).catch(() => null)
    if (body && body.split(/\s+/).some((w) => tokenEq(w, token))) return { ok: true, method: 'file', looked }
  }
  if (methods.includes('meta')) {
    const url = `https://${host}/`
    looked.push(`<meta name="${META_NAME}"> at ${url}`)
    const html = await get(url).catch(() => null)
    if (html && hasMeta(html, token)) return { ok: true, method: 'meta', looked }
  }
  return { ok: false, looked }
}

/** A <meta name="autohacker-verify" content="<token>"> anywhere in the homepage HTML, attributes in any order. */
export function hasMeta(html: string, token: string): boolean {
  const metas = html.match(/<meta\b[^>]*>/gi) ?? []
  for (const tag of metas) {
    const name = tag.match(/\bname\s*=\s*["']?([^"'\s>]+)/i)?.[1]?.toLowerCase()
    if (name !== META_NAME) continue
    const content = tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1] ?? tag.match(/\bcontent\s*=\s*([^"'\s>]+)/i)?.[1]
    if (content && tokenEq(content.trim(), token)) return true
  }
  return false
}

/** Human-readable proof instructions for a host + token (web, CLI and the verify API all render from this). */
export function proofInstructions(host: string, token: string) {
  return {
    host,
    token,
    dns: { name: `${DNS_LABEL}.${host}`, type: 'TXT', value: `${DNS_PREFIX}${token}` },
    file: { url: `https://${host}/.well-known/autohacker-${token}.txt`, body: token },
    meta: { tag: `<meta name="${META_NAME}" content="${token}">`, where: `the homepage of https://${host}/` },
  }
}
