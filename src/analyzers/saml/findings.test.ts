import { describe, expect, it } from 'vitest'
import { decodeSaml } from './decoder'
import { samlResponseFixture } from './fixtures'
import { evaluateSaml } from './findings'

const NOW = Date.UTC(2026, 0, 1, 0, 30)

function decode(opts: Parameters<typeof samlResponseFixture>[0] = {}) {
  return decodeSaml(samlResponseFixture(opts))
}

describe('evaluateSaml', () => {
  it('healthy signed assertion produces no findings', () => {
    const d = decode({
      signed: true,
      notBefore: '2026-01-01T00:00:00Z',
      notOnOrAfter: '2026-01-01T01:00:00Z',
    })
    expect(evaluateSaml(d, { now: NOW })).toEqual([])
  })

  it('flags missing signature as error', () => {
    const d = decode({ signed: false, notBefore: '2026-01-01T00:00:00Z', notOnOrAfter: '2026-01-01T01:00:00Z' })
    const f = evaluateSaml(d, { now: NOW })
    expect(f.find((x) => x.id === 'saml.signature.missing')?.severity).toBe('error')
  })

  it('flags SHA-1 signature algorithm as warning', () => {
    const d = decode({
      signed: true,
      signatureAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
      notBefore: '2026-01-01T00:00:00Z',
      notOnOrAfter: '2026-01-01T01:00:00Z',
    })
    expect(evaluateSaml(d, { now: NOW }).some((f) => f.id === 'saml.signature.weakAlgorithm')).toBe(true)
  })

  it('flags SHA-1 digest as warning', () => {
    const d = decode({
      signed: true,
      digestAlg: 'http://www.w3.org/2000/09/xmldsig#sha1',
      notBefore: '2026-01-01T00:00:00Z',
      notOnOrAfter: '2026-01-01T01:00:00Z',
    })
    expect(evaluateSaml(d, { now: NOW }).some((f) => f.id === 'saml.signature.weakDigest')).toBe(true)
  })

  it('flags expired assertions', () => {
    const d = decode({ signed: true, notBefore: '2025-01-01T00:00:00Z', notOnOrAfter: '2025-12-31T23:59:59Z' })
    const f = evaluateSaml(d, { now: NOW })
    expect(f.find((x) => x.id === 'saml.conditions.expired')?.severity).toBe('error')
  })

  it('flags assertions not yet valid', () => {
    const d = decode({ signed: true, notBefore: '2027-01-01T00:00:00Z', notOnOrAfter: '2027-01-02T00:00:00Z' })
    const f = evaluateSaml(d, { now: NOW })
    expect(f.find((x) => x.id === 'saml.conditions.notYetValid')?.severity).toBe('warning')
  })

  it('flags missing audience restriction', () => {
    const d = decode({ signed: true, notBefore: '2026-01-01T00:00:00Z', notOnOrAfter: '2026-01-01T01:00:00Z', audience: null })
    expect(evaluateSaml(d, { now: NOW }).some((f) => f.id === 'saml.conditions.noAudience')).toBe(true)
  })

  it('flags encrypted assertions as info', () => {
    const d = decode({ encrypted: true })
    const f = evaluateSaml(d, { now: NOW })
    expect(f.find((x) => x.id === 'saml.assertion.encrypted')?.severity).toBe('info')
  })

  it('flags unknown root as warning', () => {
    const d = decodeSaml('<root xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><foo/></root>')
    expect(evaluateSaml(d, { now: NOW }).some((f) => f.id === 'saml.kind.unknown')).toBe(true)
  })

  it('flags missing Conditions on a non-encrypted assertion', () => {
    const xml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.test/</saml:Issuer>
      <saml:Subject><saml:NameID>x</saml:NameID></saml:Subject>
    </saml:Assertion>`
    const d = decodeSaml(xml)
    expect(evaluateSaml(d, { now: NOW }).some((f) => f.id === 'saml.conditions.missing')).toBe(true)
  })

  it('flags missing issuer', () => {
    const xml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Subject><saml:NameID>x</saml:NameID></saml:Subject>
    </saml:Assertion>`
    const d = decodeSaml(xml)
    expect(evaluateSaml(d, { now: NOW }).some((f) => f.id === 'saml.issuer.missing')).toBe(true)
  })
})
