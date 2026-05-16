import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { decodeSamlMetadata } from './decoder'
import { evaluateSamlMetadata } from './findings'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

function decode(name: string) {
  const d = decodeSamlMetadata(read(name))
  if (!d) throw new Error(`expected ${name} to decode`)
  return d
}

// "now" inside the 10-year validity window of good.pem (2026-05-16 → 2036-05-13)
// but well clear of the 30-day expiringSoon window.
const NOW = Date.UTC(2026, 5, 1)

describe('evaluateSamlMetadata', () => {
  it('produces no findings on a healthy signed IdP', () => {
    expect(evaluateSamlMetadata(decode('idp.xml'), { now: NOW })).toEqual([])
  })

  it('flags an unsigned metadata document as warning', () => {
    const findings = evaluateSamlMetadata(decode('unsigned.xml'), { now: NOW })
    const hit = findings.find((f) => f.id === 'samlMeta.signing.missing')
    expect(hit?.severity).toBe('warning')
  })

  it('flags an expired signing certificate as error', () => {
    const findings = evaluateSamlMetadata(decode('expired-cert.xml'), { now: NOW })
    const hit = findings.find((f) => f.id === 'samlMeta.cert.expired')
    expect(hit?.severity).toBe('error')
  })

  it('flags an expiringSoon signing certificate as warning when notAfter is < 30 days', () => {
    const decoded = decode('idp.xml')
    const certs = decoded.entities[0].roles[0].signingCerts
    const notAfter = certs[0].notAfter.getTime()
    // Fix the clock to 5 days before the cert expires.
    const findings = evaluateSamlMetadata(decoded, { now: notAfter - 5 * 24 * 60 * 60 * 1000 })
    const hit = findings.find((f) => f.id === 'samlMeta.cert.expiringSoon')
    expect(hit?.severity).toBe('warning')
  })

  it('flags an entity with no IDPSSO/SPSSO descriptor as warning', () => {
    const decoded = decodeSamlMetadata(
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://x/"></md:EntityDescriptor>`
    )!
    const findings = evaluateSamlMetadata(decoded, { now: NOW })
    expect(findings.some((f) => f.id === 'samlMeta.role.missing')).toBe(true)
  })

  it('does not emit cert.expired when no signing certs are declared', () => {
    const decoded = decodeSamlMetadata(
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        entityID="https://nocerts.example.test/">
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
        <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        </md:IDPSSODescriptor>
      </md:EntityDescriptor>`
    )!
    const findings = evaluateSamlMetadata(decoded, { now: NOW })
    expect(findings.find((f) => f.id === 'samlMeta.cert.expired')).toBeUndefined()
    expect(findings.find((f) => f.id === 'samlMeta.cert.expiringSoon')).toBeUndefined()
  })

  it('annotates per-entity findings with the entityID when multiple entities are present', () => {
    const decoded = decode('entities.xml')
    const findings = evaluateSamlMetadata(decoded, { now: NOW })
    const spUnsigned = findings.find(
      (f) => f.id === 'samlMeta.signing.missing' && f.message.includes('https://sp.example.test/')
    )
    expect(spUnsigned).toBeDefined()
  })

  it('uses Date.now() when no options.now is supplied', () => {
    // expired-cert.xml's notAfter is in 2024; against real `now` this must still fire.
    const findings = evaluateSamlMetadata(decode('expired-cert.xml'))
    expect(findings.some((f) => f.id === 'samlMeta.cert.expired')).toBe(true)
  })
})
