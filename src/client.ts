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
  /** Your webhook endpoints, and the events auto.hacker sends. */
  webhooks(): Promise<{ endpoints: any[]; event_types: string[] }> { return this.req('GET', '/api/v1/webhooks') }
  addWebhook(url: string, events?: string[], description = ''): Promise<{ endpoint: any; secret: string }> { return this.req('POST', '/api/v1/webhooks', { url, ...(events?.length ? { events } : {}), description }) }
  removeWebhook(id: string) { return this.req('DELETE', `/api/v1/webhooks/${encodeURIComponent(id)}`) }
  testWebhook(id: string): Promise<{ ok: boolean; status: number | null; error: string | null }> { return this.req('POST', `/api/v1/webhooks/${encodeURIComponent(id)}/test`) }
  rotateWebhook(id: string): Promise<{ secret: string }> { return this.req('POST', `/api/v1/webhooks/${encodeURIComponent(id)}/rotate`) }
  webhookLog(id?: string): Promise<{ deliveries: any[] }> { return this.req('GET', id ? `/api/v1/webhooks/${encodeURIComponent(id)}/deliveries` : '/api/v1/webhooks/deliveries') }
}
