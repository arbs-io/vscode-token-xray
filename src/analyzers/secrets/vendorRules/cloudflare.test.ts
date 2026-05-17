import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { CLOUDFLARE_SECRET_RULES } from './cloudflare'

const opts = { rules: CLOUDFLARE_SECRET_RULES }

const HEX37 = 'a'.repeat(37)
const HEX64 = 'b'.repeat(64)
const HEX32 = 'c'.repeat(32)
const TUNNEL = 'A'.repeat(120)

describe('CLOUDFLARE_SECRET_RULES — global API key', () => {
  it('matches X-Auth-Key header', () => {
    const text = `X-Auth-Key: ${HEX37}`
    const hits = scanForSecrets(text, opts)
    const hit = hits.find((h) => h.rule.id === 'secret.cloudflare.globalApiKey')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX37)
  })

  it('matches case-insensitively', () => {
    expect(
      scanForSecrets(`x-auth-key: ${HEX37}`, opts).some(
        (h) => h.rule.id === 'secret.cloudflare.globalApiKey'
      )
    ).toBe(true)
  })

  it('does not match 36 or 38 hex chars (must be exactly 37)', () => {
    expect(scanForSecrets(`X-Auth-Key: ${'a'.repeat(36)}`, opts)).toEqual([])
  })

  it('does not match non-hex chars', () => {
    expect(scanForSecrets(`X-Auth-Key: ${'g'.repeat(37)}`, opts)).toEqual([])
  })
})

describe('CLOUDFLARE_SECRET_RULES — scoped API token (labelled)', () => {
  const TOKEN = 'A'.repeat(40)

  it('matches CLOUDFLARE_API_TOKEN=...', () => {
    const text = `CLOUDFLARE_API_TOKEN=${TOKEN}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.cloudflare.apiToken')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(TOKEN)
  })

  it('matches CF_API_TOKEN=...', () => {
    expect(
      scanForSecrets(`CF_API_TOKEN="${TOKEN}"`, opts).some(
        (h) => h.rule.id === 'secret.cloudflare.apiToken'
      )
    ).toBe(true)
  })

  it('does not match a bare 40-char string', () => {
    expect(scanForSecrets(TOKEN, opts).filter((h) => h.rule.id === 'secret.cloudflare.apiToken')).toEqual([])
  })
})

describe('CLOUDFLARE_SECRET_RULES — Access client_id', () => {
  it('matches CF_ACCESS_CLIENT_ID with <hex32>.access.<host> form (info)', () => {
    const text = `CF_ACCESS_CLIENT_ID=${HEX32}.access.example.com`
    const hits = scanForSecrets(text, opts)
    const hit = hits.find((h) => h.rule.id === 'secret.cloudflare.accessClientId')
    expect(hit?.rule.severity).toBe('info')
  })

  it('rejects mismatched format', () => {
    expect(scanForSecrets('CF_ACCESS_CLIENT_ID=not-the-format', opts)).toEqual([])
  })
})

describe('CLOUDFLARE_SECRET_RULES — Access client_secret', () => {
  it('matches CF_ACCESS_CLIENT_SECRET= 64+ hex', () => {
    const text = `CF_ACCESS_CLIENT_SECRET=${HEX64}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.cloudflare.accessClientSecret'
    )
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX64)
  })

  it('rejects too-short hex strings', () => {
    expect(scanForSecrets('CF_ACCESS_CLIENT_SECRET=abc123', opts)).toEqual([])
  })
})

describe('CLOUDFLARE_SECRET_RULES — Tunnel token', () => {
  it('matches CF_TUNNEL_TOKEN= long base64-ish value', () => {
    const text = `CF_TUNNEL_TOKEN=${TUNNEL}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.cloudflare.tunnelToken')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(TUNNEL)
  })

  it('matches TUNNEL_TOKEN= alias', () => {
    const text = `TUNNEL_TOKEN=${TUNNEL}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.cloudflare.tunnelToken')
    ).toBe(true)
  })

  it('rejects too-short values', () => {
    expect(scanForSecrets('CF_TUNNEL_TOKEN=short', opts)).toEqual([])
  })
})

describe('CLOUDFLARE_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of CLOUDFLARE_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.cloudflare', () => {
    for (const r of CLOUDFLARE_SECRET_RULES) {
      expect(r.id.startsWith('secret.cloudflare.')).toBe(true)
    }
  })
})
