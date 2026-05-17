import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { AUTH0_SECRET_RULES } from './auth0'

const opts = { rules: AUTH0_SECRET_RULES }

const SECRET_32 = 'abcdefghijklmnopqrstuvwxyz012345'
const SECRET_64 = SECRET_32 + SECRET_32

describe('AUTH0_SECRET_RULES — client_secret', () => {
  it('matches AUTH0_CLIENT_SECRET=... (32-char minimum)', () => {
    const text = `AUTH0_CLIENT_SECRET=${SECRET_32}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.auth0.clientSecret')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(SECRET_32)
  })

  it('matches 64-char modern Auth0 secrets', () => {
    const text = `auth0_client_secret: "${SECRET_64}"`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.auth0.clientSecret')
    ).toBe(true)
  })

  it('matches camelCase auth0ClientSecret', () => {
    const text = `{ "auth0ClientSecret": "${SECRET_32}" }`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.auth0.clientSecret')
    ).toBe(true)
  })

  it('rejects too-short values', () => {
    expect(scanForSecrets('AUTH0_CLIENT_SECRET=short', opts)).toEqual([])
  })
})

describe('AUTH0_SECRET_RULES — Management API token', () => {
  const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig'

  it('matches AUTH0_API_TOKEN=<jwt>', () => {
    const text = `AUTH0_API_TOKEN=${JWT}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.auth0.managementApiToken'
    )
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(JWT)
  })

  it('matches AUTH0_MGMT_TOKEN alias', () => {
    expect(
      scanForSecrets(`AUTH0_MGMT_TOKEN=${JWT}`, opts).some(
        (h) => h.rule.id === 'secret.auth0.managementApiToken'
      )
    ).toBe(true)
  })

  it('matches AUTH0_MANAGEMENT_TOKEN alias', () => {
    expect(
      scanForSecrets(`AUTH0_MANAGEMENT_TOKEN="${JWT}"`, opts).some(
        (h) => h.rule.id === 'secret.auth0.managementApiToken'
      )
    ).toBe(true)
  })

  it('rejects values that are not JWT-shaped', () => {
    expect(scanForSecrets('AUTH0_API_TOKEN=not-a-jwt-just-words', opts)).toEqual([])
  })
})

describe('AUTH0_SECRET_RULES — tenant domain', () => {
  it('matches AUTH0_DOMAIN=tenant.auth0.com (info)', () => {
    const text = 'AUTH0_DOMAIN=my-tenant.auth0.com'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.auth0.tenantDomain')
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe('my-tenant.auth0.com')
  })

  it('matches region-qualified tenants', () => {
    expect(
      scanForSecrets('AUTH0_DOMAIN=my-tenant.eu.auth0.com', opts).some(
        (h) => h.rule.id === 'secret.auth0.tenantDomain'
      )
    ).toBe(true)
  })

  it('rejects non-auth0 domains', () => {
    expect(scanForSecrets('AUTH0_DOMAIN=example.com', opts)).toEqual([])
  })
})

describe('AUTH0_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of AUTH0_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.auth0', () => {
    for (const r of AUTH0_SECRET_RULES) {
      expect(r.id.startsWith('secret.auth0.')).toBe(true)
    }
  })
})
