/** auto.hacker's server-rendered pages. Plain strings; no client framework. */
import { FIELDS } from '@profullstack/profile'
import { ringFooter } from './ring-footer.ts'
import { pitFooter } from './pit-footer.ts'
import { RING_PLACEHOLDER } from './ring.ts'
import type { Run, Target, User, Schedule, Finding } from './db.ts'
import { VERSION } from './version.ts'
import type { PublicEndpoint } from '@profullstack/webhooks'
import { WEBHOOK_EVENTS } from './service.ts'

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
export const esc = (v: unknown) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]!)

export type Ctx = { origin: string; user: User | null; crawlproof?: string | null; selfProof?: string | null }

const sev = (s: string) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`

const nav = (ctx: Ctx) => `
  <header class="top">
    <a class="brand" href="/"><span class="brand-mark">&gt;_</span> auto<span class="dot">.</span>hacker</a>
    <nav>
      <a href="/manifesto">Manifesto</a>
      <a href="/docs">API</a>
      ${ctx.user ? `<a href="/targets">Targets</a> <a href="/runs">Runs</a> <a href="/account">Account</a> <form method="post" action="/logout" class="inline"><button class="link">Sign out</button></form>` : `<a href="/login">Sign in</a>`}
    </nav>
  </header>`

export function layout(ctx: Ctx, opts: { title: string; desc: string; body: string; publicPage?: boolean }): string {
  const stats = opts.publicPage && ctx.crawlproof ? `<script defer src="https://crawlproof.com/stats.js" data-site="${esc(ctx.crawlproof)}"></script>` : ''
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(opts.title)}</title>
<meta name="description" content="${esc(opts.desc)}">
${ctx.selfProof ? `<meta name="autohacker-verify" content="${esc(ctx.selfProof)}">` : ""}
<link rel="icon" href="/favicon.svg">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="stylesheet" href="/style.css">
${stats}
</head>
<body>
${RING_PLACEHOLDER}
${nav(ctx)}
<main>
${opts.body}
</main>
${ringFooter()}
${pitFooter()}
<footer class="ver"><span>auto.hacker v${VERSION} · authorized, non-destructive testing of your own verified sites</span></footer>
</body>
</html>`
}

export function homePage(ctx: Ctx): string {
  const body = `
  <section class="hero">
    <h1>Pentest sites you own. <em>Only</em> sites you own.</h1>
    <p class="lead">auto.hacker runs a non-destructive security scan against a website — missing headers, reflected-XSS markers, CORS and cookie flags, CSP, directory listing, error disclosure, sensitive paths, unsafe methods. It will not touch a host until you have <strong>proven you control it</strong>.</p>
    <div class="cta">
      ${ctx.user ? `<a class="btn" href="/targets">Add a target</a>` : `<a class="btn" href="/login">Sign in to start</a>`}
      <a class="btn ghost" href="/manifesto">Read the manifesto</a>
    </div>
  </section>
  <section class="steps">
    <div class="step"><h3>1 · Prove ownership</h3><p>Add a hostname and publish one of three proofs: a DNS <code>TXT</code> record, a <code>/.well-known</code> file, or a <code>&lt;meta&gt;</code> tag. We check it live.</p></div>
    <div class="step"><h3>2 · Scan</h3><p>Launch a scan. Ownership is re-checked at launch and again in the worker before a single request is sent. Findings stream in live.</p></div>
    <div class="step"><h3>3 · Watch it over time</h3><p>Subscribe a verified host to weekly scans and get an emailed summary of new, fixed and open findings.</p></div>
  </section>
  <section class="honest">
    <p><strong>Honest about what this is:</strong> authorized testing of your own verified properties, with non-destructive checks only. The engine is <a href="https://github.com/profullstack/threatcrush">ThreatCrush</a>. This is not a substitute for a manual penetration test.</p>
  </section>`
  return layout(ctx, { title: 'auto.hacker — authorized website pentests', desc: 'Authorized, non-destructive website pentest service. Scan only sites you have proven you own. Powered by ThreatCrush. Web, API, CLI, TUI and MCP.', body, publicPage: true })
}

export function manifestoPage(ctx: Ctx): string {
  const body = `
  <article class="prose">
    <h1>The auto.hacker manifesto</h1>
    <p>Automated security scanners are useful and dangerous for the same reason: they send traffic at a target without asking. We built auto.hacker on one rule that makes the danger go away.</p>
    <h2>One rule</h2>
    <p><strong>No scan runs against a host until the person asking has proven they control that exact host — and the proof is re-checked the moment the scan launches, and again right before the first request.</strong> A target you cannot prove you own is refused. There is no override, no allow-list, no "just this once".</p>
    <h2>How you prove it</h2>
    <p>Pick one, per host. We give you a token that is unique to your account and that host:</p>
    <ul>
      <li><strong>DNS TXT</strong> — <code>_autohacker.&lt;host&gt;</code> set to <code>autohacker-verify=&lt;token&gt;</code>.</li>
      <li><strong>File</strong> — <code>https://&lt;host&gt;/.well-known/autohacker-&lt;token&gt;.txt</code> containing the token.</li>
      <li><strong>Meta tag</strong> — <code>&lt;meta name="autohacker-verify" content="&lt;token&gt;"&gt;</code> on the homepage.</li>
    </ul>
    <h2>What we do, and don't</h2>
    <p>The checks are non-destructive: GET requests and one-shot probes with short timeouts, no payload delivery, no exploitation. We keep an immutable authorization log of every verification. We rate-limit scans per host. We never accept a raw URL into the engine without the ownership check in the same code path.</p>
    <p>This is not a manual penetration test and does not pretend to be. It is a fast, repeatable, <em>authorized</em> first pass you can run on your own sites as often as you like.</p>
    <p class="muted">Surfaces: web, JSON API, <code>autohacker</code> CLI, MCP server and a TUI. Engine: ThreatCrush. A Moshpit name on the <a href="https://pit.world">pit.world</a> network.</p>
  </article>`
  return layout(ctx, { title: 'Manifesto — auto.hacker', desc: 'Why auto.hacker only ever scans sites you have proven you own.', body, publicPage: true })
}

export function loginPage(ctx: Ctx, opts: { next?: string | null; sent?: boolean } = {}): string {
  const body = opts.sent
    ? `<section class="narrow"><h1>Check your email</h1><p>If that address has access, a one-time sign-in link is on its way. It works once, for 20 minutes.</p></section>`
    : `<section class="narrow">
        <h1>Sign in</h1>
        <p class="muted">We email you a one-time link. No password. First time in creates your account.</p>
        <form method="post" action="/login">
          ${opts.next ? `<input type="hidden" name="next" value="${esc(opts.next)}">` : ''}
          <label>Email<input type="email" name="email" required autocomplete="email" placeholder="you@example.com"></label>
          <button class="btn" type="submit">Email me a link</button>
        </form>
      </section>`
  return layout(ctx, { title: 'Sign in — auto.hacker', desc: 'Sign in to auto.hacker.', body })
}

export function accountPage(ctx: Ctx, opts: { apiKey?: string; profile?: Record<string, string | null> | null; paid?: boolean; flash?: string; webhooks?: PublicEndpoint[]; webhookSecret?: string }): string {
  const p = opts.profile ?? {}
  const fields = FIELDS.map((f) => `<label>${esc(f.label)}<input type="${f.type}" name="${f.name}" value="${esc(p[f.name] ?? '')}" ${f.name === 'email' ? 'readonly' : ''} placeholder="${esc(f.placeholder ?? '')}" maxlength="${f.maxLength}"></label>`).join('\n')
  const body = `
  <section class="narrow">
    <h1>Account</h1>
    ${opts.paid ? `<p class="ok">Thanks — scheduled scans are enabled on your account.</p>` : ''}
    <h2>Profile</h2>
    <form method="post" action="/account/profile" class="grid">
      ${fields}
      <button class="btn" type="submit">Save profile</button>
    </form>
    <h2>API key</h2>
    <p class="muted">For the <code>autohacker</code> CLI, the MCP server and the API. Making a new key replaces the old one.</p>
    ${opts.apiKey ? `<pre class="key">${esc(opts.apiKey)}</pre><p class="muted">Copy it now — it is shown once.</p>` : ''}
    <form method="post" action="/account/key"><button class="btn ghost" type="submit">${opts.apiKey ? 'Regenerate' : 'Create'} API key</button></form>
    <h2 id="webhooks">Webhooks</h2>
    <p class="muted">auto.hacker POSTs what happens to your targets and scans to your URL: ${WEBHOOK_EVENTS.map((e) => `<code>${esc(e)}</code>`).join(', ')}. CloudEvents JSON, signed per <a href="https://www.standardwebhooks.com/">Standard Webhooks</a> (verify with <code>@profullstack/webhooks</code> or any Standard Webhooks library); retried for about three days. Findings carry severity and title only; the detail stays in the signed-in report.</p>
    ${opts.flash ? `<p class="ok">${esc(opts.flash)}</p>` : ''}
    ${opts.webhookSecret ? `<p class="muted">Signing secret:</p><pre class="key">${esc(opts.webhookSecret)}</pre>` : ''}
    ${(opts.webhooks ?? []).map((w) => `<div class="row"><code>${esc(w.url)}</code> <span class="muted">${esc(w.events.join(', '))}${w.enabled ? '' : ` · off: ${esc(w.disabled_reason ?? 'disabled')}`}</span>
      ${(['test', 'rotate', 'delete'] as const).map((a) => `<form method="post" action="/account/webhooks/${a}" class="inline"><input type="hidden" name="id" value="${esc(w.id)}"><button class="btn sm ${a === 'test' ? '' : 'ghost'}" type="submit">${a === 'test' ? 'Send a test' : a === 'rotate' ? 'New secret' : 'Remove'}</button></form>`).join('')}</div>`).join('')}
    <form method="post" action="/account/webhooks/add" class="row"><input name="url" type="url" required placeholder="https://example.com/hooks/autohacker" aria-label="Webhook URL"><input name="events" placeholder="Events (blank = all, or run.*, finding.created)" aria-label="Events"><button class="btn" type="submit">Add webhook</button></form>
    <p class="muted">Also from the CLI (<code>autohacker webhooks</code>), MCP and <code>/api/v1/webhooks</code>.</p>
    <h2>Scheduled scans</h2>
    <p class="muted">Free scans run on demand against your verified sites. Scheduled, recurring scans with emailed summaries are the paid tier.</p>
    <form method="post" action="/account/checkout"><button class="btn" type="submit">Enable scheduled scans — pay with CoinPay</button></form>
  </section>`
  return layout(ctx, { title: 'Account — auto.hacker', desc: 'Your account.', body })
}

function stateBadge(t: Target): string {
  const label = t.state === 'verified' ? 'verified' : t.state === 'lapsed' ? 'lapsed' : 'unverified'
  return `<span class="state state-${t.state}">${label}</span>`
}

export function targetsPage(ctx: Ctx, targets: Target[], opts: { error?: string; added?: string } = {}): string {
  const rows = targets.length
    ? targets.map((t) => `
      <li class="target">
        <div class="target-head"><a href="/targets/${esc(t.id)}"><code>${esc(t.host)}</code></a> ${stateBadge(t)}</div>
        <div class="target-actions">
          <a class="btn sm ghost" href="/targets/${esc(t.id)}">Proof &amp; verify</a>
          <form method="post" action="/targets/${esc(t.id)}/scan" class="inline"><button class="btn sm" ${t.state === 'verified' ? '' : 'disabled title="Verify ownership first"'}>Launch scan</button></form>
        </div>
      </li>`).join('')
    : `<li class="muted">No targets yet. Add a hostname you own below.</li>`
  const body = `
  <section>
    <h1>Targets</h1>
    ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ''}
    ${opts.added ? `<p class="ok">Added <code>${esc(opts.added)}</code>. Now prove you own it.</p>` : ''}
    <form method="post" action="/targets" class="row">
      <input type="text" name="host" placeholder="example.com" required autocomplete="off">
      <button class="btn" type="submit">Add target</button>
    </form>
    <ul class="targets">${rows}</ul>
  </section>`
  return layout(ctx, { title: 'Targets — auto.hacker', desc: 'Your targets.', body })
}

export function targetPage(ctx: Ctx, t: Target, proof: ReturnType<typeof import('./gate.ts').proofInstructions>, runs: Run[], schedule: Schedule | null, opts: { error?: string; verified?: boolean } = {}): string {
  const runRows = runs.length ? runs.map((r) => `<li><a href="/runs/${esc(r.id)}">${new Date(r.createdAt).toISOString().slice(0, 16).replace('T', ' ')}</a> — <span class="rstatus rstatus-${esc(r.status)}">${esc(r.status)}</span> ${r.summary ? `· ${esc(r.summary)}` : ''}</li>`).join('') : '<li class="muted">No scans yet.</li>'
  const body = `
  <section>
    <p><a href="/targets">← Targets</a></p>
    <h1><code>${esc(t.host)}</code> ${stateBadge(t)}</h1>
    ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ''}
    ${opts.verified ? `<p class="ok">Ownership verified. You can scan this host.</p>` : ''}
    <h2>Prove you own this host</h2>
    <p class="muted">Publish <strong>one</strong> of these, then press Verify. The token is unique to your account and this host.</p>
    <div class="proof">
      <h3>DNS TXT record</h3>
      <pre>${esc(proof.dns.name)}  TXT  "${esc(proof.dns.value)}"</pre>
      <h3>Or a file</h3>
      <pre>${esc(proof.file.url)}
(body: ${esc(proof.file.body)})</pre>
      <h3>Or a meta tag on the homepage</h3>
      <pre>${esc(proof.meta.tag)}</pre>
    </div>
    <form method="post" action="/targets/${esc(t.id)}/verify" class="inline"><button class="btn" type="submit">Verify now</button></form>
    <form method="post" action="/targets/${esc(t.id)}/scan" class="inline"><button class="btn" ${t.state === 'verified' ? '' : 'disabled'}>Launch scan</button></form>
    <h2>Scheduled scans</h2>
    ${schedule && schedule.active
      ? `<p>Scanning <strong>${esc(schedule.cadence)}</strong>, next ${new Date(schedule.nextAt).toISOString().slice(0, 10)}. <form method="post" action="/targets/${esc(t.id)}/unsubscribe" class="inline"><button class="link">Stop</button></form></p>`
      : `<form method="post" action="/targets/${esc(t.id)}/subscribe" class="inline">
           <select name="cadence"><option value="weekly">weekly</option><option value="daily">daily</option><option value="monthly">monthly</option></select>
           <button class="btn sm" ${t.state === 'verified' ? '' : 'disabled title="Verify first"'}>Subscribe</button>
         </form>`}
    <h2>Scan history</h2>
    <ul class="runs">${runRows}</ul>
  </section>`
  return layout(ctx, { title: `${t.host} — auto.hacker`, desc: `Ownership and scans for ${t.host}.`, body })
}

export function runsPage(ctx: Ctx, runs: Run[]): string {
  const rows = runs.length ? runs.map((r) => `<li><a href="/runs/${esc(r.id)}"><code>${esc(r.host)}</code></a> — <span class="rstatus rstatus-${esc(r.status)}">${esc(r.status)}</span> · ${new Date(r.createdAt).toISOString().slice(0, 16).replace('T', ' ')} ${r.summary ? `· ${esc(r.summary)}` : ''}</li>`).join('') : '<li class="muted">No runs yet.</li>'
  return layout(ctx, { title: 'Runs — auto.hacker', desc: 'Your scan runs.', body: `<section><h1>Runs</h1><ul class="runs">${rows}</ul></section>` })
}

export function runPage(ctx: Ctx, run: Run, findings: Finding[]): string {
  const live = run.status === 'queued' || run.status === 'running'
  const findingRows = findings.map((f) => `<tr><td>${sev(f.severity)}</td><td>${esc(f.type)}</td><td>${esc(f.message)}</td><td class="loc">${esc(f.location)}</td></tr>`).join('')
  const body = `
  <section>
    <p><a href="/runs">← Runs</a></p>
    <h1>Scan of <code>${esc(run.host)}</code></h1>
    <p>Status: <span class="rstatus rstatus-${esc(run.status)}" id="status">${esc(run.status)}</span> ${run.summary ? `· <span id="summary">${esc(run.summary)}</span>` : '<span id="summary"></span>'}</p>
    ${run.status === 'refused' ? `<p class="err">${esc(run.error ?? 'Refused: ownership not proven.')}</p>` : ''}
    <div class="exports">
      <a class="btn sm ghost" href="/api/v1/runs/${esc(run.id)}/export.json">Export JSON</a>
      <a class="btn sm ghost" href="/api/v1/runs/${esc(run.id)}/export.csv">Export CSV</a>
    </div>
    <div id="log" class="scanlog" aria-live="polite"></div>
    <table class="findings"><thead><tr><th>Severity</th><th>Type</th><th>Message</th><th>Location</th></tr></thead>
      <tbody id="findings">${findingRows}</tbody></table>
    ${live ? `<script>
      const es = new EventSource('/api/v1/runs/${esc(run.id)}/stream');
      const log = document.getElementById('log'), tbody = document.getElementById('findings');
      const add = (c, t) => { const d = document.createElement('div'); d.className = c; d.textContent = t; log.appendChild(d); };
      es.addEventListener('step', e => add('step', JSON.parse(e.data).note));
      es.addEventListener('finding', e => { const f = JSON.parse(e.data).finding; const tr = document.createElement('tr'); tr.innerHTML = '<td><span class="sev sev-'+f.severity+'">'+f.severity+'</span></td><td></td><td></td><td class="loc"></td>'; tr.children[1].textContent=f.type; tr.children[2].textContent=f.message; tr.children[3].textContent=f.location; tbody.appendChild(tr); });
      es.addEventListener('status', e => { document.getElementById('status').textContent = JSON.parse(e.data).status; });
      es.addEventListener('done', e => { const d = JSON.parse(e.data); document.getElementById('status').textContent='done'; document.getElementById('summary').textContent=d.summary; add('done','Scan complete.'); es.close(); });
      es.addEventListener('refused', e => { document.getElementById('status').textContent='refused'; add('err', JSON.parse(e.data).error); es.close(); });
      es.addEventListener('error', e => { try { add('err', JSON.parse(e.data).error); } catch(_){} });
    </script>` : ''}
  </section>`
  return layout(ctx, { title: `Scan of ${run.host} — auto.hacker`, desc: `Scan findings for ${run.host}.`, body })
}

export function messagePage(ctx: Ctx, opts: { title: string; message: string }, status = 200): string {
  return layout(ctx, { title: `${opts.title} — auto.hacker`, desc: opts.message, body: `<section class="narrow"><h1>${esc(opts.title)}</h1><p>${esc(opts.message)}</p></section>` })
}
