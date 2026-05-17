import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { SamlMetadataAnalyzer } from './analyzer'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

const NOW = Date.UTC(2026, 5, 1)

describe('SamlMetadataAnalyzer', () => {
  const analyzer = new SamlMetadataAnalyzer({ now: NOW })

  it('exposes id and human name', () => {
    expect(analyzer.id).toBe('samlMetadata')
    expect(analyzer.name).toBe('SAML 2.0 metadata')
  })

  it('detects a single-entity IdP', () => {
    const matches = analyzer.detect(read('idp.xml'))
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBe(read('idp.xml').indexOf('<md:EntityDescriptor'))
  })

  it('detects an EntitiesDescriptor wrapper', () => {
    const matches = analyzer.detect(read('entities.xml'))
    expect(matches).toHaveLength(1)
  })

  it('does not match arbitrary text', () => {
    expect(analyzer.detect('hello world')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('does not match SAML assertion XML (different root element)', () => {
    const xml = `<saml:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>x</saml:Issuer></saml:Response>`
    expect(analyzer.detect(xml)).toEqual([])
  })

  it('skips a candidate when decodeSamlMetadata returns undefined', () => {
    // EntityDescriptor without entityID should not be reported even though the regex matches.
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>`
    expect(analyzer.detect(xml)).toEqual([])
  })

  it('produces an entity section with entityID, roles, NameIDFormats, signing cert rows', () => {
    const [m] = analyzer.detect(read('idp.xml'))
    const result = analyzer.analyze(m)
    expect(result.analyzerId).toBe('samlMetadata')
    expect(result.kind).toBe('EntityDescriptor (IdP)')
    expect(result.sections).toHaveLength(1)
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('entityID')
    expect(keys).toContain('roles')
    expect(keys).toContain('nameIDFormats')
    expect(keys).toContain('signingCert')
    expect(keys).toContain('signed')
  })

  it('renders AssertionConsumerService URLs for SP entities', () => {
    const [m] = analyzer.detect(read('sp.xml'))
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('EntityDescriptor (SP)')
    const acsRow = result.sections[0].rows.find((r) => r.key === 'assertionConsumerServices')
    expect(acsRow).toBeDefined()
    expect(String(acsRow!.value)).toContain('https://sp.example.test/acs')
  })

  it('emits one section per entity in a multi-entity document', () => {
    const [m] = analyzer.detect(read('entities.xml'))
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('EntitiesDescriptor')
    expect(result.sections).toHaveLength(2)
    const titles = result.sections.map((s) => s.title)
    expect(titles[0]).toContain('https://idp.example.test/')
    expect(titles[1]).toContain('https://sp.example.test/')
  })

  it('surfaces samlMeta.signing.missing on an unsigned IdP', () => {
    const [m] = analyzer.detect(read('unsigned.xml'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'samlMeta.signing.missing')?.severity).toBe(
      'warning'
    )
  })

  it('surfaces samlMeta.cert.expired on an expired-cert IdP', () => {
    const [m] = analyzer.detect(read('expired-cert.xml'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'samlMeta.cert.expired')?.severity).toBe('error')
  })

  it('throws on analyze() with non-metadata input', () => {
    expect(() => analyzer.analyze({ text: '<root/>' })).toThrow(/SAML 2\.0 metadata/)
  })

  it('reports kind=EntityDescriptor for an entity with no descriptors', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://x/"></md:EntityDescriptor>`
    const [m] = analyzer.detect(xml)
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('EntityDescriptor')
    expect(result.sections[0].rows.find((r) => r.key === 'signingCerts')?.value).toBe('(none)')
  })

  it('extracts the metadata block out of surrounding noise', () => {
    const text = `# notes\nrandom text\n${read('idp.xml')}\nmore text`
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBeGreaterThan(0)
  })

  it('renders multiple signing certs with indexed keys', () => {
    const certBase64 =
      'MIIDmDCCAoCgAwIBAgIUQf+PjcchJeGRFb8hSPDDVnd96XYwDQYJKoZIhvcNAQELBQAwPjEaMBgGA1UEAwwRZ29vZC5leGFtcGxlLnRlc3QxEzARBgNVBAoMCkV4YW1wbGUgQ28xCzAJBgNVBAYTAlVTMB4XDTI2MDUxNjE2MjAyMFoXDTM2MDUxMzE2MjAyMFowPjEaMBgGA1UEAwwRZ29vZC5leGFtcGxlLnRlc3QxEzARBgNVBAoMCkV4YW1wbGUgQ28xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2WpxbJTiQx9DkETg3/lYk2/yjFcsxiU3d8vU7Es4kDYszvS8ftFS9rjVRJqMIhHsNZuOENR9PaIrugVJ0ZGmE1vvwLNQ8AmBLewgjbfNR/HKrNk+li0AdSOsnUYD4sYJZ5z+CQqw6mwZFjyHaO2wwT9+yps+CzHqc6MRomcl0kfcZYKNzNYbw2FdJxHoGKfn5NBhDRi2beZq9Hk60MAmcGA6JoaVl4IGSAN0PuK31AkdS/bZCNqP/H6uihrfJOvHDAvqvEeDJ+ps8WumfEj/8dJLyVYalBrqOI+N7w6LzAGywZXjQyaHi+oERM3eF0Vq4dDCKvZKXl6ohhjHOQR8MQIDAQABo4GNMIGKMB0GA1UdDgQWBBTpcmpQpDUx+dUOkwICfjwb7aSguDAfBgNVHSMEGDAWgBTpcmpQpDUx+dUOkwICfjwb7aSguDAPBgNVHRMBAf8EBTADAQH/MDcGA1UdEQQwMC6CEWdvb2QuZXhhbXBsZS50ZXN0ghMqLmdvb2QuZXhhbXBsZS50ZXN0hwQKAAABMA0GCSqGSIb3DQEBCwUAA4IBAQCAE0VHGWsa6k/AXMCMUw9bHAG0PazCPGbm8QizKL9BLp69xI9lckPEL9zueCtkv3p9R7a6ytmoOfzqPlFx875cIoLDooic1TXvJ2NSsVLMAeFI7vzYPKHEz16/RhNMGd7FO7LYurZU1X7BvSHBsUJ09dlVtAN9hK2h+mMg35bORj8QdD4rOkQgNmWLZC5pjYd130KOU0qqb+2tdhpKgMi/iUWZ/ST3GIrgXqdw6o3wDuahZ6SlAIyzWuHZtA1o3m7IGodSFbY/6w7F79j+fF4kz5bwLE3zk3xfi9P22KVACoftPf5zJ+FkahRey+2tXE4JpanULhTcd0BaaaN7VbuJ'
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      entityID="https://twokeys.example.test/">
      <ds:Signature/>
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certBase64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certBase64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>`
    const [m] = analyzer.detect(xml)
    const result = analyzer.analyze(m)
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('signingCert[0]')
    expect(keys).toContain('signingCert[1]')
  })
})
