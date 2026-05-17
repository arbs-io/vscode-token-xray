import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { decodeOidcDiscovery } from './decoder'
import { evaluateOidcDiscovery } from './findings'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

function decode(name: string) {
  const d = decodeOidcDiscovery(read(name))
  if (!d) throw new Error(`expected ${name} to decode`)
  return d
}

describe('evaluateOidcDiscovery', () => {
  it('produces no findings on a healthy config', () => {
    const findings = evaluateOidcDiscovery(decode('healthy.json'))
    expect(findings).toEqual([])
  })

  it('flags `none` in id_token_signing_alg_values_supported as error', () => {
    const findings = evaluateOidcDiscovery(decode('malicious-none.json'))
    const hit = findings.find((f) => f.id === 'oidcDiscovery.algs.noneAllowed')
    expect(hit?.severity).toBe('error')
  })

  it('matches `none` case-insensitively', () => {
    const decoded = decodeOidcDiscovery(
      JSON.stringify({
        issuer: 'https://idp',
        jwks_uri: 'https://idp/jwks',
        authorization_endpoint: 'https://idp/auth',
        id_token_signing_alg_values_supported: ['RS256', 'NONE'],
      })
    )!
    const findings = evaluateOidcDiscovery(decoded)
    expect(findings.some((f) => f.id === 'oidcDiscovery.algs.noneAllowed')).toBe(true)
  })

  it('flags HS256 as info', () => {
    const findings = evaluateOidcDiscovery(decode('mixed-hs256.json'))
    const hit = findings.find((f) => f.id === 'oidcDiscovery.algs.weakHs256Allowed')
    expect(hit?.severity).toBe('info')
  })

  it('emits notHttps for each non-HTTPS endpoint', () => {
    const findings = evaluateOidcDiscovery(decode('http-endpoint.json'))
    const httpHits = findings.filter((f) => f.id === 'oidcDiscovery.endpoint.notHttps')
    // issuer + authorization_endpoint + token_endpoint + userinfo_endpoint + jwks_uri = 5 entries
    expect(httpHits).toHaveLength(5)
    expect(httpHits.every((f) => f.severity === 'warning')).toBe(true)
  })

  it('mentions the offending field label in the message', () => {
    const decoded = decodeOidcDiscovery(
      JSON.stringify({
        issuer: 'https://idp',
        jwks_uri: 'http://idp/jwks',
        authorization_endpoint: 'https://idp/auth',
      })
    )!
    const findings = evaluateOidcDiscovery(decoded)
    expect(findings).toHaveLength(1)
    expect(findings[0].message).toContain('jwks_uri')
    expect(findings[0].message).toContain('http://idp/jwks')
  })

  it('does not flag https URLs even with mixed-case scheme', () => {
    const decoded = decodeOidcDiscovery(
      JSON.stringify({
        issuer: 'HTTPS://idp',
        jwks_uri: 'Https://idp/jwks',
        authorization_endpoint: 'https://idp/auth',
      })
    )!
    const findings = evaluateOidcDiscovery(decoded)
    expect(findings.filter((f) => f.id === 'oidcDiscovery.endpoint.notHttps')).toHaveLength(0)
  })

  it('does not emit alg findings when the list is absent', () => {
    const decoded = decodeOidcDiscovery(
      JSON.stringify({
        issuer: 'https://idp',
        jwks_uri: 'https://idp/jwks',
        authorization_endpoint: 'https://idp/auth',
      })
    )!
    const findings = evaluateOidcDiscovery(decoded)
    expect(findings.find((f) => f.id.startsWith('oidcDiscovery.algs.'))).toBeUndefined()
  })

  it('emits both none and HS256 findings when both are present', () => {
    const decoded = decodeOidcDiscovery(
      JSON.stringify({
        issuer: 'https://idp',
        jwks_uri: 'https://idp/jwks',
        authorization_endpoint: 'https://idp/auth',
        id_token_signing_alg_values_supported: ['none', 'HS256', 'RS256'],
      })
    )!
    const ids = evaluateOidcDiscovery(decoded).map((f) => f.id)
    expect(ids).toContain('oidcDiscovery.algs.noneAllowed')
    expect(ids).toContain('oidcDiscovery.algs.weakHs256Allowed')
  })
})
