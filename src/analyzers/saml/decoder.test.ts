import { describe, expect, it } from 'vitest'
import { decodeSaml, looksLikeSamlXml, normaliseSamlInput } from './decoder'
import { samlResponseFixture, toBase64, toRedirectEncoded } from './fixtures'

describe('looksLikeSamlXml', () => {
  it('identifies SAML-namespaced XML', () => {
    expect(looksLikeSamlXml(samlResponseFixture())).toBe(true)
  })

  it('rejects arbitrary XML', () => {
    expect(looksLikeSamlXml('<foo/>')).toBe(false)
  })

  it('rejects non-XML', () => {
    expect(looksLikeSamlXml('not xml at all')).toBe(false)
  })
})

describe('normaliseSamlInput', () => {
  it('returns raw XML untouched', () => {
    const xml = samlResponseFixture()
    expect(normaliseSamlInput(xml)).toBe(xml.trim())
  })

  it('decodes base64-encoded SAML', () => {
    const xml = samlResponseFixture()
    const out = normaliseSamlInput(toBase64(xml))
    expect(out).toContain('samlp:Response')
  })

  it('decodes HTTP-Redirect-encoded SAML (DEFLATE + base64 + URL-encode)', () => {
    const xml = samlResponseFixture()
    const out = normaliseSamlInput(toRedirectEncoded(xml))
    expect(out).toContain('samlp:Response')
  })

  it('throws when the input is neither XML nor base64', () => {
    expect(() => normaliseSamlInput('this has spaces and is not base64')).toThrow()
  })

  it('throws when base64 decodes to non-SAML content', () => {
    expect(() => normaliseSamlInput(toBase64('hello world'))).toThrow(/not recognisable/)
  })
})

describe('decodeSaml', () => {
  it('extracts issuer, subject, conditions, audience from a fixture Response', () => {
    const result = decodeSaml(samlResponseFixture({ signed: true }))
    expect(result.kind).toBe('Response')
    expect(result.issuer).toBe('https://idp.example.test/')
    expect(result.subject?.nameId).toBe('alice@example.test')
    expect(result.conditions?.audiences).toEqual(['https://sp.example.test/'])
    expect(result.signature.present).toBe(true)
    expect(result.signature.algorithm).toContain('rsa-sha256')
  })

  it('reports unsigned assertions', () => {
    const result = decodeSaml(samlResponseFixture({ signed: false }))
    expect(result.signature.present).toBe(false)
  })

  it('flags EncryptedAssertion', () => {
    const result = decodeSaml(samlResponseFixture({ encrypted: true }))
    expect(result.isEncrypted).toBe(true)
    expect(result.subject).toBeUndefined()
  })

  it('parses a bare <Assertion> root', () => {
    const xml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.test/</saml:Issuer>
      <saml:Subject><saml:NameID>bob</saml:NameID></saml:Subject>
    </saml:Assertion>`
    const result = decodeSaml(xml)
    expect(result.kind).toBe('Assertion')
    expect(result.subject?.nameId).toBe('bob')
  })

  it('returns unknown for non-SAML root elements that still parse as XML', () => {
    const xml = `<root xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><foo/></root>`
    const result = decodeSaml(xml)
    expect(result.kind).toBe('unknown')
  })
})
