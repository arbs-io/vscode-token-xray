import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { OidcDiscoveryAnalyzer } from './analyzer'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

describe('OidcDiscoveryAnalyzer', () => {
  const analyzer = new OidcDiscoveryAnalyzer()

  it('exposes id and human name', () => {
    expect(analyzer.id).toBe('oidcDiscovery')
    expect(analyzer.name).toBe('OIDC discovery document')
  })

  it('detects a healthy discovery document', () => {
    const matches = analyzer.detect(read('healthy.json'))
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBe(0)
  })

  it('covers the entire document text', () => {
    const text = read('healthy.json')
    const [m] = analyzer.detect(text)
    expect(m.text).toBe(text)
    expect(m.range?.end).toBe(text.length)
  })

  it('detects whitespace-prefixed documents', () => {
    const text = '   \n  ' + read('healthy.json')
    expect(analyzer.detect(text)).toHaveLength(1)
  })

  it('does not detect arbitrary JSON without OIDC required fields', () => {
    expect(analyzer.detect('{"foo": 1}')).toEqual([])
    expect(analyzer.detect('{"keys": [{"kty":"RSA"}]}')).toEqual([])
  })

  it('does not detect non-JSON text', () => {
    expect(analyzer.detect('hello world')).toEqual([])
    expect(analyzer.detect('   ')).toEqual([])
  })

  it('returns empty match list for empty input', () => {
    expect(analyzer.detect('')).toEqual([])
  })

  it('does not detect when leading non-whitespace is not `{`', () => {
    // JSON-shape gate must reject content that begins with a JWT, XML, etc.
    expect(analyzer.detect('eyJhbGciOiJIUzI1NiJ9.eyJ4Ijoid"}')).toEqual([])
    expect(analyzer.detect('<EntityDescriptor></EntityDescriptor>')).toEqual([])
  })

  it('produces sections with endpoints', () => {
    const [m] = analyzer.detect(read('healthy.json'))
    const result = analyzer.analyze(m)
    expect(result.analyzerId).toBe('oidcDiscovery')
    expect(result.kind).toBe('OIDC discovery document')
    const overview = result.sections.find((s) => s.id === 'overview')
    expect(overview).toBeDefined()
    const keys = overview!.rows.map((r) => r.key)
    expect(keys).toContain('issuer')
    expect(keys).toContain('jwks_uri')
    expect(keys).toContain('authorization_endpoint')
    expect(keys).toContain('token_endpoint')
    expect(keys).toContain('userinfo_endpoint')
  })

  it('produces a capabilities section when algs / scopes / response_types are present', () => {
    const [m] = analyzer.detect(read('healthy.json'))
    const caps = analyzer.analyze(m).sections.find((s) => s.id === 'capabilities')
    expect(caps).toBeDefined()
    const keys = caps!.rows.map((r) => r.key)
    expect(keys).toContain('id_token_signing_alg_values_supported')
    expect(keys).toContain('scopes_supported')
    expect(keys).toContain('response_types_supported')
  })

  it('omits the capabilities section when nothing is present', () => {
    const text = JSON.stringify({
      issuer: 'https://idp',
      jwks_uri: 'https://idp/jwks',
      authorization_endpoint: 'https://idp/auth',
    })
    const [m] = analyzer.detect(text)
    const result = analyzer.analyze(m)
    expect(result.sections.find((s) => s.id === 'capabilities')).toBeUndefined()
  })

  it('omits optional token / userinfo endpoints when absent', () => {
    const text = JSON.stringify({
      issuer: 'https://idp',
      jwks_uri: 'https://idp/jwks',
      authorization_endpoint: 'https://idp/auth',
    })
    const [m] = analyzer.detect(text)
    const overview = analyzer.analyze(m).sections.find((s) => s.id === 'overview')!
    const keys = overview.rows.map((r) => r.key)
    expect(keys).not.toContain('token_endpoint')
    expect(keys).not.toContain('userinfo_endpoint')
  })

  it('surfaces the noneAllowed finding on a malicious config', () => {
    const [m] = analyzer.detect(read('malicious-none.json'))
    const findings = analyzer.analyze(m).findings
    expect(findings.find((f) => f.id === 'oidcDiscovery.algs.noneAllowed')?.severity).toBe('error')
  })

  it('surfaces the weakHs256Allowed finding on a mixed config', () => {
    const [m] = analyzer.detect(read('mixed-hs256.json'))
    const findings = analyzer.analyze(m).findings
    expect(findings.find((f) => f.id === 'oidcDiscovery.algs.weakHs256Allowed')?.severity).toBe('info')
  })

  it('surfaces the notHttps finding for HTTP endpoints', () => {
    const [m] = analyzer.detect(read('http-endpoint.json'))
    const findings = analyzer.analyze(m).findings
    expect(findings.some((f) => f.id === 'oidcDiscovery.endpoint.notHttps')).toBe(true)
  })

  it('throws on analyze() with a non-OIDC payload', () => {
    expect(() => analyzer.analyze({ text: '{"foo":1}' })).toThrow(/OIDC discovery/)
  })
})
