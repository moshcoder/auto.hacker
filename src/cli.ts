/**
 * `autohacker` — the command line for the same verbs as the web and API.
 * Authorization-first: `scan` only succeeds once `verify` has passed for the host.
 *
 *   autohacker add <host>                 add a target, print the proof to publish
 *   autohacker proof <host>               reprint the proof for a host
 *   autohacker verify <host> [--method m] re-check the live proof
 *   autohacker scan <host> [--wait]       launch a scan (refused if unproven)
 *   autohacker runs                       list recent runs
 *   autohacker report <runId>             print a run's findings
 *   autohacker targets                    list targets and their state
 *   autohacker webhooks                   your webhook endpoints and the events sent
 *   autohacker webhook add <url> [events...]  POST scan events to your URL (prints the secret)
 *   autohacker webhook test|rotate|rm <id>    send a test, replace the secret, or remove it
 *   autohacker webhook log [id]           recent deliveries
 *
 * Config: AUTOHACKER_URL (default https://auto.hacker.pit.world), AUTOHACKER_API_KEY.
 */
import { Client } from './client.ts'
import { VERSION } from './version.ts'

const flag = (args: string[], name: string): string | undefined => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined }
const has = (args: string[], name: string) => args.includes(`--${name}`)

async function targetFor(c: Client, host: string): Promise<any> {
  const { targets } = await c.targets()
  return targets.find((t: any) => t.host === host.toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, ''))
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const [cmd, ...rest] = argv
  const c = new Client()
  try {
    switch (cmd) {
      case 'add': {
        const { target, proof } = await c.addTarget(rest[0]!)
        console.log(`Added ${target.host} (${target.state}). Publish ONE proof, then: autohacker verify ${target.host}\n`)
        printProof(proof); return 0
      }
      case 'proof': {
        const t = await targetFor(c, rest[0]!); if (!t) { console.error('No such target; add it first.'); return 1 }
        const { proof } = await c.target(t.id)
        printProof(proof); return 0
      }
      case 'verify': {
        const t = await targetFor(c, rest[0]!); if (!t) { console.error('No such target; add it first.'); return 1 }
        const r = await c.verify(t.id, flag(rest, 'method'))
        console.log(r.ok ? `✓ verified (${r.method})` : `✗ not verified yet. Looked: ${r.looked.join('; ')}`); return r.ok ? 0 : 2
      }
      case 'scan': {
        let run: any
        try { run = (await c.scan({ host: rest[0] })).run } catch (e) { console.error(`Refused: ${(e as Error).message}`); return 3 }
        console.log(`Scan ${run.id} queued for ${run.host}.`)
        if (has(rest, 'wait')) {
          for (let i = 0; i < 60; i++) {
            await new Promise((r) => setTimeout(r, 2000))
            const { run: cur, findings } = await c.run(run.id)
            if (cur.status === 'done' || cur.status === 'error' || cur.status === 'refused') { console.log(`\n${cur.status}: ${cur.summary ?? cur.error ?? ''}`); printFindings(findings); return cur.status === 'done' ? 0 : 3 }
          }
          console.log('Still running; check `autohacker report ' + run.id + '`.')
        }
        return 0
      }
      case 'runs': { const { runs } = await c.runs(); for (const r of runs) console.log(`${r.id}  ${r.status.padEnd(8)}  ${r.host}  ${r.summary ?? ''}`); return 0 }
      case 'report': { const { run, findings } = await c.run(rest[0]!); console.log(`${run.host} — ${run.status} — ${run.summary ?? run.error ?? ''}`); printFindings(findings); return 0 }
      case 'targets': { const { targets } = await c.targets(); for (const t of targets) console.log(`${t.state.padEnd(11)} ${t.host}`); return 0 }
      case 'webhooks': {
        const r = await c.webhooks()
        for (const w of r.endpoints) console.log(`${w.id}  ${w.url}  ${w.events.join(',')}${w.enabled ? '' : `  OFF (${w.disabled_reason})`}`)
        if (!r.endpoints.length) console.log('no webhooks')
        console.log(`events: ${r.event_types.join(', ')}`); return 0
      }
      case 'webhook': {
        const [sub, arg, ...more] = rest
        if (sub === 'add' && arg) { const r = await c.addWebhook(arg, more); console.log(`${r.endpoint.id} -> ${r.endpoint.url}\nsigning secret: ${r.secret}`); return 0 }
        if (sub === 'test' && arg) { const r = await c.testWebhook(arg); console.log(r.ok ? `delivered (HTTP ${r.status})` : `failed: ${r.error}`); return r.ok ? 0 : 2 }
        if (sub === 'rotate' && arg) { console.log(`new signing secret: ${(await c.rotateWebhook(arg)).secret}`); return 0 }
        if ((sub === 'rm' || sub === 'remove' || sub === 'delete') && arg) { await c.removeWebhook(arg); console.log('removed'); return 0 }
        if (sub === 'log') { const r = await c.webhookLog(arg); for (const d of r.deliveries) console.log(`${String(d.created_at).slice(0, 19)}  ${String(d.event_type).padEnd(16)} ${String(d.status).padEnd(9)} x${d.attempts} ${d.last_status ?? ''} ${d.last_error ?? ''}`); if (!r.deliveries.length) console.log('no deliveries yet'); return 0 }
        console.error('Usage: autohacker webhook add <url> [events...] | test <id> | rotate <id> | rm <id> | log [id]'); return 1
      }
      case 'stats': { console.log(JSON.stringify(await c.stats(), null, 2)); return 0 }
      case 'version': case '--version': case '-v': console.log(VERSION); return 0
      default:
        console.log(`autohacker v${VERSION}\n\nUsage:\n  autohacker add <host>\n  autohacker proof <host>\n  autohacker verify <host> [--method dns|file|meta]\n  autohacker scan <host> [--wait]\n  autohacker runs\n  autohacker report <runId>\n  autohacker targets\n  autohacker webhooks\n  autohacker webhook add <url> [events...] | test <id> | rotate <id> | rm <id> | log [id]\n\nEnv: AUTOHACKER_URL, AUTOHACKER_API_KEY (make one on your account page).`)
        return cmd ? 1 : 0
    }
  } catch (e) { console.error((e as Error).message); return 1 }
}

function printProof(p: any) {
  console.log(`  DNS TXT : ${p.dns.name}  TXT  "${p.dns.value}"`)
  console.log(`  File    : ${p.file.url}  (body: ${p.file.body})`)
  console.log(`  Meta    : ${p.meta.tag}`)
}
function printFindings(findings: any[]) {
  if (!findings?.length) { console.log('  (no findings)'); return }
  for (const f of findings) console.log(`  [${f.severity.toUpperCase()}] ${f.type} — ${f.message}\n     ${f.location}`)
}

if (import.meta.main) process.exit(await main())
