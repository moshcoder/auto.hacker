import { expect, test, describe } from 'bun:test'
import {
  normalizeHost, verifyToken, checkOwnership, hasMeta, privateIp,
  DNS_LABEL, DNS_PREFIX, META_NAME, type GateDeps,
} from '../src/gate.ts'

const SECRET = 'x'.repeat(32)
const USER = 'user-abc'
const HOST = 'example.com'

describe('normalizeHost', () => {
  test('strips scheme, path, port, www kept as-is', () => {
    expect(normalizeHost('https://Example.com:8443/path?q=1')).toBe('example.com')
    expect(normalizeHost('  sub.example.co.uk  ')).toBe('sub.example.co.uk')
    expect(normalizeHost('example.com.')).toBe('example.com')
  })
  test('refuses IP literals, localhost, internal and junk', () => {
    for (const bad of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '::1', 'localhost', 'box.local', 'svc.internal', 'no-dot', '', 'a..b', 'http://']) {
      expect(normalizeHost(bad)).toBeNull()
    }
  })
})

test('privateIp catches private/loopback/link-local', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.1', '172.16.0.1', '169.254.1.1', '::1', 'fd00::1', 'fe80::1']) expect(privateIp(ip)).toBe(true)
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) expect(privateIp(ip)).toBe(false)
})

test('verifyToken is stable per (user,host) and differs across them', () => {
  const t = verifyToken(SECRET, USER, HOST)
  expect(t).toBe(verifyToken(SECRET, USER, 'https://EXAMPLE.com/'))   // normalized, stable
  expect(t).not.toBe(verifyToken(SECRET, USER, 'other.com'))
  expect(t).not.toBe(verifyToken(SECRET, 'user-xyz', HOST))
  expect(t.length).toBe(32)
})

test('verifyToken refuses an unscannable host and an unset secret', () => {
  expect(() => verifyToken(SECRET, USER, '127.0.0.1')).toThrow()
  expect(() => verifyToken('short', USER, HOST)).toThrow()
})

const tok = verifyToken(SECRET, USER, HOST)

describe('checkOwnership — the gate', () => {
  test('DNS TXT proof passes only with the exact value', async () => {
    const deps: GateDeps = { resolveTxt: async (n) => (n === `${DNS_LABEL}.${HOST}` ? [[`${DNS_PREFIX}${tok}`]] : []) }
    const r = await checkOwnership({ host: HOST, token: tok }, deps)
    expect(r.ok).toBe(true)
    expect(r.method).toBe('dns')
  })

  test('split TXT chunks are joined before comparison', async () => {
    const half = Math.floor(tok.length / 2)
    const deps: GateDeps = { resolveTxt: async () => [[`${DNS_PREFIX}${tok.slice(0, half)}`, tok.slice(half)]] }
    expect((await checkOwnership({ host: HOST, token: tok }, deps)).ok).toBe(true)
  })

  test('file proof passes when the body contains the token', async () => {
    const deps: GateDeps = {
      resolveTxt: async () => [],
      fetchText: async (u) => (u === `https://${HOST}/.well-known/autohacker-${tok}.txt` ? `${tok}\n` : null),
    }
    const r = await checkOwnership({ host: HOST, token: tok }, deps)
    expect(r.ok).toBe(true)
    expect(r.method).toBe('file')
  })

  test('meta proof passes when the homepage carries the tag', async () => {
    const deps: GateDeps = {
      resolveTxt: async () => [],
      fetchText: async (u) => (u === `https://${HOST}/` ? `<html><head><meta name="${META_NAME}" content="${tok}"></head></html>` : null),
    }
    const r = await checkOwnership({ host: HOST, token: tok }, deps)
    expect(r.ok).toBe(true)
    expect(r.method).toBe('meta')
  })

  test('REFUSES a host with no proof anywhere', async () => {
    const deps: GateDeps = { resolveTxt: async () => [], fetchText: async () => null }
    const r = await checkOwnership({ host: HOST, token: tok }, deps)
    expect(r.ok).toBe(false)
    expect(r.method).toBeUndefined()
    expect(r.looked.length).toBe(3)
  })

  test("REFUSES when the proof is for a DIFFERENT user (wrong token)", async () => {
    const otherTok = verifyToken(SECRET, 'intruder', HOST)
    const deps: GateDeps = { resolveTxt: async () => [[`${DNS_PREFIX}${otherTok}`]] }
    expect((await checkOwnership({ host: HOST, token: tok }, deps)).ok).toBe(false)
  })

  test("REFUSES when the proof is on a DIFFERENT host", async () => {
    // Proof exists for attacker.com but the user claims victim.com
    const deps: GateDeps = { resolveTxt: async (n) => (n === `${DNS_LABEL}.attacker.com` ? [[`${DNS_PREFIX}${tok}`]] : []) }
    expect((await checkOwnership({ host: 'victim.com', token: verifyToken(SECRET, USER, 'victim.com') }, deps)).ok).toBe(false)
  })

  test('only:dns does not fall through to file/meta', async () => {
    let fetched = false
    const deps: GateDeps = { resolveTxt: async () => [], fetchText: async () => { fetched = true; return `${tok}` } }
    const r = await checkOwnership({ host: HOST, token: tok, only: 'dns' }, deps)
    expect(r.ok).toBe(false)
    expect(fetched).toBe(false)
  })

  test('an empty/blank token never passes', async () => {
    const deps: GateDeps = { resolveTxt: async () => [['autohacker-verify=']], fetchText: async () => '' }
    expect((await checkOwnership({ host: HOST, token: '' }, deps)).ok).toBe(false)
  })
})

describe('hasMeta', () => {
  test('matches attributes in any order and single quotes', () => {
    expect(hasMeta(`<meta content='${tok}' name='${META_NAME}'>`, tok)).toBe(true)
    expect(hasMeta(`<META NAME="${META_NAME}" CONTENT="${tok}">`, tok)).toBe(true)
  })
  test('rejects a different name or a near-miss token', () => {
    expect(hasMeta(`<meta name="description" content="${tok}">`, tok)).toBe(false)
    expect(hasMeta(`<meta name="${META_NAME}" content="${tok}x">`, tok)).toBe(false)
  })
})
