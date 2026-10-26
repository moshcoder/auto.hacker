/**
 * auto.hacker MCP server (stdio). Same verbs as the CLI and API; an agent can add
 * a target, read the proof, verify, scan (refused unless proven) and read a report.
 * Auth via AUTOHACKER_API_KEY. Run: `autohacker mcp`.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { Client } from './client.ts'
import { VERSION } from './version.ts'

export function buildServer(client = new Client()): McpServer {
  const server = new McpServer({ name: 'auto.hacker', version: VERSION })
  const text = (o: unknown) => ({ content: [{ type: 'text' as const, text: typeof o === 'string' ? o : JSON.stringify(o, null, 2) }] })
  const findTarget = async (host: string) => {
    const { targets } = await client.targets()
    return targets.find((t: any) => t.host === host.toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, ''))
  }

  server.tool('add_target', 'Add a host you want to scan and get the ownership proof to publish.', { host: z.string() }, async ({ host }) => text(await client.addTarget(host)))
  server.tool('get_proof', 'Reprint the ownership proof (DNS/file/meta) for a host.', { host: z.string() }, async ({ host }) => {
    const t = await findTarget(host); if (!t) return text('No such target; add it first.')
    return text((await client.target(t.id)).proof)
  })
  server.tool('verify', 'Re-check the live ownership proof for a host.', { host: z.string(), method: z.enum(['dns', 'file', 'meta']).optional() }, async ({ host, method }) => {
    const t = await findTarget(host); if (!t) return text('No such target; add it first.')
    return text(await client.verify(t.id, method))
  })
  server.tool('scan', 'Launch an authorized scan. Refused unless ownership is proven.', { host: z.string() }, async ({ host }) => {
    try { return text(await client.scan({ host })) } catch (e) { return text(`Refused: ${(e as Error).message}`) }
  })
  server.tool('runs', 'List recent scan runs.', {}, async () => text(await client.runs()))
  server.tool('report', 'Get a run and its findings by id.', { run_id: z.string() }, async ({ run_id }) => text(await client.run(run_id)))
  server.tool('targets', 'List your targets and their verification state.', {}, async () => text(await client.targets()))
  return server
}

export async function runMcp(): Promise<void> {
  const server = buildServer()
  await server.connect(new StdioServerTransport())
}

if (import.meta.main) await runMcp()
