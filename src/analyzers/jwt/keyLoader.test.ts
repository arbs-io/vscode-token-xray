import { describe, expect, it } from 'vitest'
import { keySourcesFromConfig, keySourcesFromConfigDetailed } from './keyLoader'

describe('keySourcesFromConfig', () => {
  it('returns empty array for non-array input', () => {
    expect(keySourcesFromConfig(undefined)).toEqual([])
    expect(keySourcesFromConfig(null)).toEqual([])
    expect(keySourcesFromConfig('nope')).toEqual([])
  })

  it('skips invalid entries', () => {
    expect(keySourcesFromConfig([null, 1, 'x', {}])).toEqual([])
  })

  it('maps PEM SPKI public keys', () => {
    const result = keySourcesFromConfig([
      { pem: '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----', alg: 'RS256', kid: 'k1' },
    ])
    expect(result).toEqual([
      expect.objectContaining({ kind: 'pem-spki', alg: 'RS256', kid: 'k1' }),
    ])
  })

  it('maps PEM X509 certificates separately from SPKI', () => {
    const result = keySourcesFromConfig([
      { pem: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----', alg: 'RS256' },
    ])
    expect(result[0].kind).toBe('pem-x509')
  })

  it('maps symmetric secrets', () => {
    const result = keySourcesFromConfig([{ secret: 's3cret-value', alg: 'HS256', kid: 'k' }])
    expect(result).toEqual([
      expect.objectContaining({ kind: 'symmetric', secret: 's3cret-value', alg: 'HS256', kid: 'k' }),
    ])
  })

  it('maps JWK objects detected by kty', () => {
    const result = keySourcesFromConfig([{ kty: 'EC', crv: 'P-256', x: 'abc', y: 'def', alg: 'ES256' }])
    expect(result).toHaveLength(1)
    expect(result[0].kind).toBe('jwk')
  })

  it('skips entries missing alg', () => {
    expect(keySourcesFromConfig([{ pem: '...' }, { secret: 'x' }])).toEqual([])
  })
})

describe('keySourcesFromConfigDetailed', () => {
  it('returns issues with the original index for invalid entries', () => {
    const { sources, issues } = keySourcesFromConfigDetailed([
      { pem: '...' },                          // missing alg
      { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }, // valid jwk
      null,                                    // null entry
      'nope',                                  // wrong type
    ])
    expect(sources).toHaveLength(1)
    expect(issues).toEqual([
      { index: 0, reason: expect.stringContaining('missing string "alg"') },
      { index: 2, reason: expect.stringContaining('null/undefined') },
      { index: 3, reason: expect.stringContaining('must be an object') },
    ])
  })

  it('returns empty issues for non-array input', () => {
    expect(keySourcesFromConfigDetailed(undefined)).toEqual({ sources: [], issues: [] })
  })

  it('reports the canonical reason for entries lacking a recognised shape', () => {
    const { issues } = keySourcesFromConfigDetailed([{ random: 'thing' }])
    expect(issues[0].reason).toMatch(/"pem"\+"alg"/)
  })
})
