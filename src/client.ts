/** Tiny HTTP client the CLI, MCP and TUI share. Auth: an account API key (ah_…). */
export type ClientOptions = { baseUrl?: string; apiKey?: string }

export class Client {
  readonly baseUrl: string
  private apiKey: string
  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? process.env.AUTOHACKER_URL ?? 'https://auto.hacker.pit.world').replace(/\/+$/, '')
    this.apiKey = opts.apiKey ?? process.env.AUTOHACKER_API_KEY ?? ''
  }
  private async req(method: string, path: string, body?: unknown): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}), ...(body ? { 'content-type': 'application/json' } : {}), accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(60_000),
    })
    const text = await res.text()
    let json: any; try { json = text ? JSON.parse(text) : {} } catch { json = { raw: text } }
    if (!res.ok) throw new Error(json?.error ?? `HTTP ${res.status}`)
    return json
  }
  me() { return this.req('GET', '/api/v1/me/profile') }
  targets() { return this.req('GET', '/api/v1/targets') }
  addTarget(host: string) { return this.req('POST', '/api/v1/targets', { host }) }
  target(id: string) { return this.req('GET', `/api/v1/targets/${id}`) }
  verify(targetId: string, method?: string) { return this.req('POST', `/api/v1/targets/${targetId}/verify`, method ? { method } : {}) }
  scan(args: { host?: string; target_id?: string }) { return this.req('POST', '/api/v1/runs', args) }
  runs() { return this.req('GET', '/api/v1/runs') }
  run(id: string) { return this.req('GET', `/api/v1/runs/${id}`) }
  stats() { return this.req('GET', '/api/v1/stats') }
}
