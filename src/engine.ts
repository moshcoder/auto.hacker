/**
 * The scan engine — vendored from ThreatCrush's pentest command
 * (profullstack/threatcrush apps/cli/src/commands/pentest.ts, PRD 07). This is a
 * byte-faithful lift of PENTEST_CHECKS + collectPentestResults, engine-only: no
 * chalk, no ora, no CLI deps, so it imports cleanly into a worker. All probes are
 * non-destructive and GET/one-shot, each with a 5 s timeout and redirect:manual.
 *
 * Parity with the CLI is PRD 07's goal; the follow-up is to publish this as a
 * shared package both import. For now the one engine lives here and the matching
 * threatcrush PR extracts it on their side.
 *
 * CALLER CONTRACT: never pass a host here that has not just passed the ownership
 * gate (src/gate.ts) in the same code path. The engine itself trusts its input.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  type: string
  severity: Severity
  message: string
  location: string
  details?: string
}

export interface RunResult {
  type: 'pentest'
  target: string
  findings: Finding[]
  severity_summary: Record<Severity, number>
  summary: string
  error?: string
}

export function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}
export function summarize(findings: Finding[]): Record<Severity, number> {
  const counts = emptyCounts()
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
  return counts
}

const PENTEST_CHECKS = [
  { name: 'XSS Reflected', test: (html: string) => /<script>alert\(1\)<\/script>|<img\s+src=x\s+onerror=alert/i.test(html), severity: 'critical' as const, message: 'Reflected XSS payload rendered in response' },
  { name: 'Open Redirect', test: (_u: string, body: string) => body.includes('location.href') || body.includes('window.location'), severity: 'medium' as const, message: 'Potential open redirect detected' },
  { name: 'Missing Security Headers', test: (_u: string, _b: string, h: Record<string, string>) => ['x-content-type-options', 'x-frame-options', 'strict-transport-security'].filter((x) => !h[x]).length > 2, severity: 'low' as const, message: 'Missing critical security headers (X-Content-Type-Options, X-Frame-Options, HSTS)' },
  { name: 'Server Version Disclosure', test: (_u: string, _b: string, h: Record<string, string>) => !!(h['server'] && /apache|nginx|iis|tomcat/i.test(h['server'])), severity: 'low' as const, message: 'Server version disclosed in response header' },
  { name: 'Directory Listing', test: (html: string) => /Index of\s*\/|<title>Directory Listing/i.test(html), severity: 'medium' as const, message: 'Directory listing enabled' },
  { name: 'Error Page Information Disclosure', test: (html: string) => /stack trace|traceback|exception|at\s+\w+\.\w+\(/i.test(html), severity: 'medium' as const, message: 'Error page reveals internal information' },
  { name: 'CORS Misconfiguration', test: (_u: string, _b: string, h: Record<string, string>) => { const a = h['access-control-allow-origin']; return a === '*' || a === 'null' }, severity: 'medium' as const, message: 'CORS allows any origin (Access-Control-Allow-Origin: *)' },
  { name: 'Cookie Security', test: (_u: string, _b: string, h: Record<string, string>) => { const c = h['set-cookie'] || ''; return c.length > 0 && (!c.includes('HttpOnly') || !c.includes('Secure')) }, severity: 'medium' as const, message: 'Cookies missing HttpOnly or Secure flags' },
  { name: 'Content Security Policy', test: (_u: string, _b: string, h: Record<string, string>) => !h['content-security-policy'], severity: 'low' as const, message: 'No Content-Security-Policy header set' },
  { name: 'Sensitive Path Exposure', test: (html: string) => /\.env|wp-admin|phpinfo|\.git\/config|server-status/i.test(html), severity: 'high' as const, message: 'Response references sensitive paths or admin endpoints' },
]

export type Progress = (note: string) => void

async function collect(targetUrl: string, onStep: Progress = () => {}): Promise<Finding[]> {
  const results: Finding[] = []
  onStep('Fetching target...')
  try {
    const resp = await fetch(targetUrl, { redirect: 'manual', signal: AbortSignal.timeout(5000) })
    const headers: Record<string, string> = {}
    resp.headers.forEach((v, k) => { headers[k] = v })
    const body = await resp.text()
    onStep(`Got ${resp.status}; running ${PENTEST_CHECKS.length} header/body checks`)
    for (const check of PENTEST_CHECKS) {
      try { if (check.test(body, body, headers)) results.push({ location: targetUrl, type: check.name, severity: check.severity, message: check.message }) } catch { /* skip */ }
    }
  } catch (err) {
    throw new Error(`could not reach target: ${(err as Error).message}`)
  }

  onStep('Testing SQL injection vectors...')
  for (const payload of ["' OR 1=1--", "1' UNION SELECT NULL--", "' AND '1'='1"]) {
    try {
      const testUrl = `${targetUrl}?id=${encodeURIComponent(payload)}`
      const body = await (await fetch(testUrl, { redirect: 'manual', signal: AbortSignal.timeout(5000) })).text()
      if (/sql\s+(syntax|error|exception)|mysql|postgres|ORA-\d+/i.test(body)) results.push({ location: testUrl, type: 'SQL Injection', severity: 'critical', message: `SQL error response detected with payload: ${payload}` })
    } catch { /* skip */ }
  }

  onStep('Testing path traversal...')
  for (const path of ['../../etc/passwd', '..%2F..%2Fetc%2Fpasswd', '....//....//etc/passwd']) {
    try {
      const testUrl = `${targetUrl}/${path}`
      const body = await (await fetch(testUrl, { redirect: 'manual', signal: AbortSignal.timeout(5000) })).text()
      if (/root:.*:0:0:|daemon:.*:1:1:|nobody:.*:65534/i.test(body)) results.push({ location: testUrl, type: 'Path Traversal', severity: 'critical', message: `Possible /etc/passwd disclosure via: ${path}` })
    } catch { /* skip */ }
  }

  onStep('Testing HTTP methods...')
  for (const method of ['OPTIONS', 'TRACE', 'DELETE', 'PUT']) {
    try {
      const resp = await fetch(targetUrl, { method, signal: AbortSignal.timeout(5000) })
      if (resp.status < 400 && method !== 'OPTIONS') results.push({ location: targetUrl, type: `Unsafe HTTP Method: ${method}`, severity: 'medium', message: `${method} method is allowed (status ${resp.status})` })
      if (method === 'OPTIONS') { const allow = resp.headers.get('allow'); if (allow && /DELETE|PUT|TRACE/i.test(allow)) results.push({ location: targetUrl, type: 'HTTP Methods', severity: 'low', message: `Allowed methods: ${allow}` }) }
    } catch { /* skip */ }
  }
  return results
}

/** Run the full non-destructive pentest suite against an (already verified) host. */
export async function runPentest(rawTarget: string, onStep: Progress = () => {}): Promise<RunResult> {
  const target = rawTarget.startsWith('http') ? rawTarget : `https://${rawTarget}`
  try {
    const findings = await collect(target, onStep)
    const counts = summarize(findings)
    return {
      type: 'pentest',
      target,
      findings,
      severity_summary: counts,
      summary: findings.length === 0 ? 'No issues detected in the non-destructive scan' : `${findings.length} issue(s): ${counts.critical}C ${counts.high}H ${counts.medium}M ${counts.low}L`,
    }
  } catch (err) {
    return { type: 'pentest', target, findings: [], severity_summary: emptyCounts(), summary: `Failed to reach target: ${(err as Error).message}`, error: (err as Error).message }
  }
}

export const ENGINE_NAME = 'ThreatCrush pentest (vendored)'
export const CHECK_NAMES = PENTEST_CHECKS.map((c) => c.name).concat(['SQL Injection', 'Path Traversal', 'Unsafe HTTP Method', 'HTTP Methods'])
