/**
 * auto.hacker's footer: its links, the << Profullstack >> webring nav and the
 * copyright line, from @profullstack/footer. Rendered server-side because the
 * webring verifier reads the page and never runs script. Kept as a string:
 * bundled template at boot, then @latest from the CDN every 15 minutes.
 */
import { footerHtml, footerHtmlSync } from '@profullstack/footer'

type FooterOptions = Parameters<typeof footerHtmlSync>[0]

export function ringFooterOptions(links: { label: string; href: string }[]): FooterOptions {
  return { site: 'https://auto.hacker.pit.world/', links, since: 2026, tagline: 'Authorized testing of your own verified sites. Free, open source (MIT).' }
}

let options: FooterOptions | null = null
let html = ''
export function setRingFooterOptions(next: FooterOptions): void { options = next; html = footerHtmlSync(next) }
export function ringFooter(): string { return html }
export function setRingFooter(next: unknown): boolean {
  if (typeof next !== 'string' || !next.includes('/ring/profullstack') || next.length > 64_000) return false
  html = next
  return true
}
export function startRingFooterRefresh(everyMs = 15 * 60_000): () => void {
  const run = () => { if (options) footerHtml(options).then(setRingFooter, () => {}) }
  run()
  const timer = setInterval(run, everyMs)
  ;(timer as { unref?: () => void }).unref?.()
  return () => clearInterval(timer)
}
