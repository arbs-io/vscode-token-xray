import { describe, expect, it } from 'vitest'
import { SamlAnalyzer } from './analyzer'
import { samlResponseFixture, toBase64 } from './fixtures'

const NOW = Date.UTC(2026, 0, 1, 0, 30)

describe('SamlAnalyzer', () => {
  const analyzer = new SamlAnalyzer({ now: NOW })

  it('detects raw SAML XML', () => {
    const xml = samlResponseFixture({ signed: true })
    const matches = analyzer.detect(xml)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toBe(xml.trim())
  })

  it('detects base64-encoded SAML', () => {
    const xml = samlResponseFixture({ signed: true })
    const b64 = toBase64(xml)
    expect(analyzer.detect(b64)).toHaveLength(1)
  })

  it('does not match arbitrary text', () => {
    expect(analyzer.detect('hello world')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces an overview section + findings', () => {
    const xml = samlResponseFixture({
      signed: true,
      notBefore: '2026-01-01T00:00:00Z',
      notOnOrAfter: '2026-01-01T01:00:00Z',
    })
    const [match] = analyzer.detect(xml)
    const result = analyzer.analyze(match)
    expect(result.analyzerId).toBe('saml')
    expect(result.kind).toBe('Response')
    expect(result.sections[0].id).toBe('overview')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('issuer')
    expect(keys).toContain('subject')
    expect(keys).toContain('audience')
    expect(keys).toContain('signature')
    expect(result.findings).toEqual([])
  })

  it('surfaces missing signature as error', () => {
    const xml = samlResponseFixture({
      signed: false,
      notBefore: '2026-01-01T00:00:00Z',
      notOnOrAfter: '2026-01-01T01:00:00Z',
    })
    const [match] = analyzer.detect(xml)
    const result = analyzer.analyze(match)
    expect(result.findings.find((f) => f.id === 'saml.signature.missing')?.severity).toBe('error')
  })

  it('renders encrypted assertions with an encrypted row', () => {
    const xml = samlResponseFixture({ encrypted: true })
    const [match] = analyzer.detect(xml)
    const result = analyzer.analyze(match)
    expect(result.sections[0].rows.some((r) => r.key === 'encrypted')).toBe(true)
  })
})
