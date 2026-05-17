import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { OKTA_SECRET_RULES } from './okta'

const opts = { rules: OKTA_SECRET_RULES }

describe('OKTA_SECRET_RULES — SSWS header', () => {
  it('matches Authorization: SSWS <token>', () => {
    const text = 'Authorization: SSWS 00abcdefghijklmnopqrstuvwxyz1234567890ABCDEF'
    const hits = scanForSecrets(text, opts)
    expect(hits.find((h) => h.rule.id === 'secret.okta.sswsHeader')?.rule.severity).toBe('error')
  })

  it('sensitiveSpan points to the token, not the SSWS keyword', () => {
    const fixture = '00abcdefghijklmnopqrstuvwxyz1234567890ABCDEF'
    const text = `Authorization: SSWS ${fixture}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.okta.sswsHeader')!
    expect(text.slice(hit.sensitiveStart, hit.sensitiveEnd)).toBe(fixture)
  })

  it('rejects SSWS with too-short token', () => {
    expect(scanForSecrets('Authorization: SSWS short', opts)).toEqual([])
  })

  it('rejects plain SSWS keyword without a token', () => {
    expect(scanForSecrets('the SSWS scheme is used', opts)).toEqual([])
  })
})

describe('OKTA_SECRET_RULES — labelled OKTA_API_TOKEN', () => {
  it('matches OKTA_API_TOKEN=...', () => {
    const text = 'OKTA_API_TOKEN=00abcdefghijklmnopqrstuvwxyz0123456789'
    const hits = scanForSecrets(text, opts)
    expect(hits.find((h) => h.rule.id === 'secret.okta.apiToken')?.rule.severity).toBe('error')
  })

  it('matches okta_api_token: "..."', () => {
    const text = 'okta_api_token: "00abcdefghijklmnopqrstuvwxyz0123456789"'
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.okta.apiToken')).toBe(true)
  })

  it('matches camelCase oktaApiToken', () => {
    const text = '{ "oktaApiToken": "00abcdefghijklmnopqrstuvwxyz0123456789" }'
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.okta.apiToken')).toBe(true)
  })

  it('sensitiveSpan covers the value only', () => {
    const fixture = '00abcdefghijklmnopqrstuvwxyz0123456789'
    const text = `OKTA_API_TOKEN=${fixture}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.okta.apiToken')!
    expect(text.slice(hit.sensitiveStart, hit.sensitiveEnd)).toBe(fixture)
  })
})

describe('OKTA_SECRET_RULES — labelled OKTA_CLIENT_SECRET', () => {
  it('matches OKTA_CLIENT_SECRET=...', () => {
    const text = 'OKTA_CLIENT_SECRET=abc123def456ghi789jkl012'
    const hits = scanForSecrets(text, opts)
    expect(hits.find((h) => h.rule.id === 'secret.okta.clientSecret')?.rule.severity).toBe('error')
  })

  it('matches camelCase oktaClientSecret with quoted value', () => {
    const text = '{ "oktaClientSecret": "abc123def456ghi789jkl012-x" }'
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.okta.clientSecret')).toBe(true)
  })

  it('rejects too-short values', () => {
    expect(scanForSecrets('OKTA_CLIENT_SECRET=short', opts)).toEqual([])
  })
})

describe('OKTA_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of OKTA_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.okta', () => {
    for (const r of OKTA_SECRET_RULES) {
      expect(r.id.startsWith('secret.okta.')).toBe(true)
    }
  })
})
