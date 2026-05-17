import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { SAILPOINT_SECRET_RULES } from './sailpoint'

const opts = { rules: SAILPOINT_SECRET_RULES }

const CLIENT_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
const CLIENT_SECRET = 'abcdefghijklmnopqrstuvwxyz0123456789ABCD-_'

describe('SAILPOINT_SECRET_RULES — client_id', () => {
  it('matches SAIL_CLIENT_ID=<hex32>', () => {
    const text = `SAIL_CLIENT_ID=${CLIENT_ID}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.sailpoint.clientId')
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(CLIENT_ID)
  })

  it('matches SAILPOINT_CLIENT_ID alias', () => {
    expect(
      scanForSecrets(`SAILPOINT_CLIENT_ID=${CLIENT_ID}`, opts).some(
        (h) => h.rule.id === 'secret.sailpoint.clientId'
      )
    ).toBe(true)
  })

  it('matches IDN_CLIENT_ID alias', () => {
    expect(
      scanForSecrets(`IDN_CLIENT_ID=${CLIENT_ID}`, opts).some(
        (h) => h.rule.id === 'secret.sailpoint.clientId'
      )
    ).toBe(true)
  })

  it('matches camelCase sailClientId', () => {
    expect(
      scanForSecrets(`{"sailClientId":"${CLIENT_ID}"}`, opts).some(
        (h) => h.rule.id === 'secret.sailpoint.clientId'
      )
    ).toBe(true)
  })

  it('rejects non-hex / wrong-length values', () => {
    expect(scanForSecrets('SAIL_CLIENT_ID=not-a-uuid-shape', opts)).toEqual([])
    expect(scanForSecrets('SAIL_CLIENT_ID=abc123', opts)).toEqual([])
  })
})

describe('SAILPOINT_SECRET_RULES — client_secret', () => {
  it('matches SAIL_CLIENT_SECRET= 40+ char base64url-ish', () => {
    const text = `SAIL_CLIENT_SECRET=${CLIENT_SECRET}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.sailpoint.clientSecret'
    )
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(CLIENT_SECRET)
  })

  it('matches ISC_CLIENT_SECRET alias', () => {
    expect(
      scanForSecrets(`ISC_CLIENT_SECRET="${CLIENT_SECRET}"`, opts).some(
        (h) => h.rule.id === 'secret.sailpoint.clientSecret'
      )
    ).toBe(true)
  })

  it('rejects too-short values', () => {
    expect(scanForSecrets('SAIL_CLIENT_SECRET=short', opts)).toEqual([])
  })

  it('does not match a bare 40-char string without label', () => {
    expect(scanForSecrets(CLIENT_SECRET, opts)).toEqual([])
  })
})

describe('SAILPOINT_SECRET_RULES — tenant URL', () => {
  it('matches SAIL_TENANT=<tenant>.api.identitynow.com (info)', () => {
    const text = 'SAIL_TENANT=acme.api.identitynow.com'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.sailpoint.tenantUrl')
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('acme.api.identitynow.com')
  })

  it('matches SAIL_BASE_URL with https://', () => {
    const text = 'SAIL_BASE_URL=https://acme.api.identitynow.com/v3'
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.sailpoint.tenantUrl')
    ).toBe(true)
  })

  it('rejects non-SailPoint domains', () => {
    expect(scanForSecrets('SAIL_TENANT=acme.example.com', opts)).toEqual([])
  })
})

describe('SAILPOINT_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of SAILPOINT_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.sailpoint', () => {
    for (const r of SAILPOINT_SECRET_RULES) {
      expect(r.id.startsWith('secret.sailpoint.')).toBe(true)
    }
  })
})
