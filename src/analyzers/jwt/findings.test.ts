import { describe, expect, it } from 'vitest'
import { evaluateJwt } from './findings'
import { DecodedJwt } from './types'

const NOW = Date.UTC(2026, 0, 1) // 2026-01-01

function decoded(overrides: Partial<DecodedJwt> = {}): DecodedJwt {
  return {
    kind: 'JWS',
    header: { alg: 'RS256', kid: 'k1' },
    payload: { exp: Math.floor(NOW / 1000) + 3600, iss: 'me', aud: 'you' },
    signature: 'sig',
    segments: ['a', 'b', 'sig'],
    raw: 'a.b.sig',
    ...overrides,
  }
}

describe('evaluateJwt', () => {
  it('returns no findings for a healthy token', () => {
    expect(evaluateJwt(decoded(), { now: NOW })).toEqual([])
  })

  it('flags alg:none as an error', () => {
    const findings = evaluateJwt(decoded({ header: { alg: 'none' } }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.alg.none')?.severity).toBe('error')
  })

  it('flags HS256 as a warning', () => {
    const findings = evaluateJwt(decoded({ header: { alg: 'HS256', kid: 'k' } }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.alg.weak')?.severity).toBe('warning')
  })

  it('flags missing alg as an error', () => {
    const findings = evaluateJwt(decoded({ header: {} }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.header.alg.missing')?.severity).toBe('error')
  })

  it('flags missing kid as info', () => {
    const findings = evaluateJwt(decoded({ header: { alg: 'RS256' } }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.header.kid.missing')?.severity).toBe('info')
  })

  it('flags crit header as warning', () => {
    const findings = evaluateJwt(decoded({ header: { alg: 'RS256', kid: 'k', crit: ['exp'] } }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.header.crit')).toBeDefined()
  })

  it('flags expired tokens', () => {
    const findings = evaluateJwt(
      decoded({ payload: { exp: Math.floor(NOW / 1000) - 1, iss: 'me', aud: 'a' } }),
      { now: NOW }
    )
    expect(findings.find((f) => f.id === 'jwt.exp.expired')?.severity).toBe('error')
  })

  it('flags non-numeric exp', () => {
    const findings = evaluateJwt(
      decoded({ payload: { exp: 'soon' as unknown as number, iss: 'me', aud: 'a' } }),
      { now: NOW }
    )
    expect(findings.find((f) => f.id === 'jwt.exp.invalid')).toBeDefined()
  })

  it('flags missing exp', () => {
    const findings = evaluateJwt(decoded({ payload: { iss: 'me', aud: 'a' } }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.exp.missing')).toBeDefined()
  })

  it('flags future nbf', () => {
    const findings = evaluateJwt(
      decoded({ payload: { exp: Math.floor(NOW / 1000) + 3600, nbf: Math.floor(NOW / 1000) + 100, iss: 'me', aud: 'a' } }),
      { now: NOW }
    )
    expect(findings.find((f) => f.id === 'jwt.nbf.future')).toBeDefined()
  })

  it('flags non-numeric nbf', () => {
    const findings = evaluateJwt(
      decoded({ payload: { exp: Math.floor(NOW / 1000) + 3600, nbf: 'soon' as unknown as number, iss: 'me', aud: 'a' } }),
      { now: NOW }
    )
    expect(findings.find((f) => f.id === 'jwt.nbf.invalid')).toBeDefined()
  })

  it('flags iat in the future', () => {
    const findings = evaluateJwt(
      decoded({ payload: { exp: Math.floor(NOW / 1000) + 3600, iat: Math.floor(NOW / 1000) + 600, iss: 'me', aud: 'a' } }),
      { now: NOW }
    )
    expect(findings.find((f) => f.id === 'jwt.iat.future')).toBeDefined()
  })

  it('flags missing aud and iss', () => {
    const findings = evaluateJwt(decoded({ payload: { exp: Math.floor(NOW / 1000) + 3600 } }), { now: NOW })
    expect(findings.find((f) => f.id === 'jwt.aud.missing')).toBeDefined()
    expect(findings.find((f) => f.id === 'jwt.iss.missing')).toBeDefined()
  })

  it('skips claim checks when payload is absent (JWE)', () => {
    const findings = evaluateJwt(
      { kind: 'JWE', header: { alg: 'RSA-OAEP', enc: 'A256GCM' }, segments: [], raw: '' },
      { now: NOW }
    )
    expect(findings.find((f) => f.id?.startsWith('jwt.exp'))).toBeUndefined()
  })

  it('emits an IdP info finding when iss matches a known issuer', () => {
    const findings = evaluateJwt(
      decoded({
        payload: {
          exp: Math.floor(NOW / 1000) + 3600,
          iss: 'https://my-tenant.okta.com/oauth2/default',
          aud: 'api',
        },
      }),
      { now: NOW }
    )
    const idp = findings.find((f) => f.id === 'jwt.idp.okta')
    expect(idp?.severity).toBe('info')
    expect(idp?.message).toContain('my-tenant')
  })

  it('does not emit an IdP finding when iss is unrecognised', () => {
    const findings = evaluateJwt(
      decoded({
        payload: {
          exp: Math.floor(NOW / 1000) + 3600,
          iss: 'https://example.com',
          aud: 'api',
        },
      }),
      { now: NOW }
    )
    expect(findings.find((f) => f.id?.startsWith('jwt.idp.'))).toBeUndefined()
  })
})
