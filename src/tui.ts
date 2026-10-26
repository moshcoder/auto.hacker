/**
 * auto.hacker TUI (@profullstack/hqtui): a terminal view of your targets and runs.
 * Thin for v0.1 — list targets with their verification state, and recent runs —
 * but a real surface. Run: `autohacker tui`.
 */
import { Client } from './client.ts'
import { VERSION } from './version.ts'

export async function runTui(): Promise<void> {
  const c = new Client()
  let hq: any = null
  try { hq = await import('@profullstack/hqtui') } catch { /* fall back to plain print */ }
  const [{ targets }, { runs }] = await Promise.all([c.targets().catch(() => ({ targets: [] })), c.runs().catch(() => ({ runs: [] }))])

  const lines = [
    `auto.hacker v${VERSION} — ${c.baseUrl}`,
    '',
    'TARGETS',
    ...(targets.length ? targets.map((t: any) => `  ${String(t.state).padEnd(11)} ${t.host}`) : ['  (none — add one with `autohacker add <host>`)']),
    '',
    'RECENT RUNS',
    ...(runs.length ? runs.slice(0, 15).map((r: any) => `  ${String(r.status).padEnd(8)} ${r.host}  ${r.summary ?? ''}`) : ['  (none)']),
  ]
  const render = hq?.renderBox ?? hq?.box ?? null
  if (render) { try { console.log(render(lines.join('\n'), { title: 'auto.hacker' })); return } catch { /* fall through */ } }
  console.log(lines.join('\n'))
}

if (import.meta.main) await runTui()
