import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { GCP_SECRET_RULES } from './gcp'

const opts = { rules: GCP_SECRET_RULES }

describe('GCP_SECRET_RULES — service account JSON', () => {
  it('flags the type marker as error', () => {
    const json = '{ "type": "service_account", "project_id": "demo" }'
    const hits = scanForSecrets(json, opts)
    expect(hits.find((h) => h.rule.id === 'secret.gcp.serviceAccount')?.rule.severity).toBe('error')
  })

  it('does not match unrelated type values', () => {
    expect(scanForSecrets('{"type": "user_account"}', opts)).toEqual([])
  })
})

describe('GCP_SECRET_RULES — API key', () => {
  it('matches a Google API key (AIza…)', () => {
    // Real Google API keys are exactly 39 chars: AIza + 35 chars from [A-Za-z0-9_-].
    const text = 'GOOGLE_API_KEY=AIzaSyA-mock_key_chars_for_demos_012345'
    const hits = scanForSecrets(text, opts)
    expect(hits.find((h) => h.rule.id === 'secret.gcp.apiKey')?.rule.severity).toBe('warning')
  })

  it('does not match short or invalid AIza-prefixed strings', () => {
    expect(scanForSecrets('AIzaShort', opts)).toEqual([])
    expect(scanForSecrets('AIza' + '!'.repeat(35), opts)).toEqual([])
  })
})

describe('GCP_SECRET_RULES — OAuth client secret', () => {
  it('matches client_secret JSON value', () => {
    const text = '{"installed":{"client_secret":"GOCSPX-abcdefghijklmnopqrst"}}'
    const hits = scanForSecrets(text, opts)
    expect(hits.find((h) => h.rule.id === 'secret.gcp.oauthClientSecret')?.rule.severity).toBe('error')
  })

  it('sensitiveSpan points to the value only', () => {
    const secret = 'GOCSPX-abcdefghijklmnopqrst'
    const text = `{"client_secret":"${secret}"}`
    const [hit] = scanForSecrets(text, opts).filter((h) => h.rule.id === 'secret.gcp.oauthClientSecret')
    expect(text.slice(hit.sensitiveStart, hit.sensitiveEnd)).toBe(secret)
  })

  it('does not match a short client_secret value', () => {
    expect(scanForSecrets('"client_secret":"short"', opts)).toEqual([])
  })
})

describe('GCP_SECRET_RULES — OAuth refresh token', () => {
  it('matches 1//... refresh token shape', () => {
    const token = '1//0g' + 'A'.repeat(60)
    const hits = scanForSecrets(`refresh=${token}`, opts)
    expect(hits.find((h) => h.rule.id === 'secret.gcp.oauthRefreshToken')?.rule.severity).toBe('error')
  })

  it('does not match short 1// prefixes', () => {
    expect(scanForSecrets('1//short', opts)).toEqual([])
  })
})

describe('GCP_SECRET_RULES — OAuth access token', () => {
  it('matches ya29 access token', () => {
    const token = 'ya29.' + 'A'.repeat(60)
    const hits = scanForSecrets(`Authorization: Bearer ${token}`, opts)
    expect(hits.find((h) => h.rule.id === 'secret.gcp.oauthAccessToken')?.rule.severity).toBe('warning')
  })
})

describe('GCP_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of GCP_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.gcp', () => {
    for (const r of GCP_SECRET_RULES) {
      expect(r.id.startsWith('secret.gcp.')).toBe(true)
    }
  })
})
