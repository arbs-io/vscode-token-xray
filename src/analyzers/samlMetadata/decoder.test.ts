import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeSamlMetadata } from './decoder'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

describe('decodeSamlMetadata', () => {
  it('decodes a single-entity IdP', () => {
    const decoded = decodeSamlMetadata(read('idp.xml'))
    expect(decoded).toBeDefined()
    if (!decoded) throw new Error('expected defined')
    expect(decoded.rootKind).toBe('EntityDescriptor')
    expect(decoded.entities).toHaveLength(1)
    const [e] = decoded.entities
    expect(e.entityId).toBe('https://idp.example.test/')
    expect(e.signed).toBe(true)
    expect(e.roles).toHaveLength(1)
    expect(e.roles[0].kind).toBe('IdP')
    expect(e.roles[0].nameIDFormats).toEqual([
      'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    ])
    expect(e.roles[0].signingCerts).toHaveLength(1)
    expect(e.roles[0].signingCerts[0].subject).toContain('good.example.test')
    expect(e.roles[0].signingCerts[0].notAfter.getTime()).toBeGreaterThan(Date.now())
  })

  it('decodes a single-entity SP with multiple AssertionConsumerService entries', () => {
    const decoded = decodeSamlMetadata(read('sp.xml'))
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities).toHaveLength(1)
    const role = decoded.entities[0].roles[0]
    expect(role.kind).toBe('SP')
    expect(role.assertionConsumerServices).toHaveLength(2)
    expect(role.assertionConsumerServices?.[0].location).toBe('https://sp.example.test/acs')
    expect(role.assertionConsumerServices?.[0].binding).toBe(
      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    )
    expect(role.assertionConsumerServices?.[1].location).toBe(
      'https://sp.example.test/acs/artifact'
    )
  })

  it('reports signed=false when no ds:Signature element is present', () => {
    const decoded = decodeSamlMetadata(read('unsigned.xml'))
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities[0].signed).toBe(false)
  })

  it('decodes a multi-entity EntitiesDescriptor', () => {
    const decoded = decodeSamlMetadata(read('entities.xml'))
    if (!decoded) throw new Error('expected defined')
    expect(decoded.rootKind).toBe('EntitiesDescriptor')
    expect(decoded.entities).toHaveLength(2)
    const kinds = decoded.entities.flatMap((e) => e.roles.map((r) => r.kind)).sort()
    expect(kinds).toEqual(['IdP', 'SP'])
    const idp = decoded.entities.find((e) => e.entityId === 'https://idp.example.test/')!
    expect(idp.signed).toBe(true)
    const sp = decoded.entities.find((e) => e.entityId === 'https://sp.example.test/')!
    expect(sp.signed).toBe(false)
  })

  it('decodes an expired-cert fixture with notAfter < now', () => {
    const decoded = decodeSamlMetadata(read('expired-cert.xml'))
    if (!decoded) throw new Error('expected defined')
    const cert = decoded.entities[0].roles[0].signingCerts[0]
    expect(cert.notAfter.getTime()).toBeLessThan(Date.now())
  })

  it('returns undefined for malformed XML', () => {
    expect(decodeSamlMetadata('<md:EntityDescriptor entityID="x"')).toBeUndefined()
  })

  it('returns undefined when text does not start with `<`', () => {
    expect(decodeSamlMetadata('not xml')).toBeUndefined()
    expect(decodeSamlMetadata('')).toBeUndefined()
  })

  it('returns undefined for SAML assertion XML (wrong root)', () => {
    const xml = `<saml:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>x</saml:Issuer></saml:Response>`
    expect(decodeSamlMetadata(xml)).toBeUndefined()
  })

  it('returns undefined for an EntityDescriptor without entityID', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>`
    expect(decodeSamlMetadata(xml)).toBeUndefined()
  })

  it('returns undefined for an empty EntitiesDescriptor', () => {
    const xml = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntitiesDescriptor>`
    expect(decodeSamlMetadata(xml)).toBeUndefined()
  })

  it('rejects non-string input', () => {
    expect(decodeSamlMetadata(undefined as unknown as string)).toBeUndefined()
    expect(decodeSamlMetadata(null as unknown as string)).toBeUndefined()
  })

  it('parses both IDPSSO and SPSSO descriptors on the same entity', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      entityID="https://dual.example.test/">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
      </md:IDPSSODescriptor>
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          Location="https://dual.example.test/acs"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>`
    const decoded = decodeSamlMetadata(xml)
    if (!decoded) throw new Error('expected defined')
    const kinds = decoded.entities[0].roles.map((r) => r.kind).sort()
    expect(kinds).toEqual(['IdP', 'SP'])
  })

  it('treats KeyDescriptors without a use attribute as signing-eligible', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      entityID="https://nokeyuse.example.test/">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor>
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIIDmDCCAoCgAwIBAgIUQf+PjcchJeGRFb8hSPDDVnd96XYwDQYJKoZIhvcNAQELBQAwPjEaMBgGA1UEAwwRZ29vZC5leGFtcGxlLnRlc3QxEzARBgNVBAoMCkV4YW1wbGUgQ28xCzAJBgNVBAYTAlVTMB4XDTI2MDUxNjE2MjAyMFoXDTM2MDUxMzE2MjAyMFowPjEaMBgGA1UEAwwRZ29vZC5leGFtcGxlLnRlc3QxEzARBgNVBAoMCkV4YW1wbGUgQ28xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2WpxbJTiQx9DkETg3/lYk2/yjFcsxiU3d8vU7Es4kDYszvS8ftFS9rjVRJqMIhHsNZuOENR9PaIrugVJ0ZGmE1vvwLNQ8AmBLewgjbfNR/HKrNk+li0AdSOsnUYD4sYJZ5z+CQqw6mwZFjyHaO2wwT9+yps+CzHqc6MRomcl0kfcZYKNzNYbw2FdJxHoGKfn5NBhDRi2beZq9Hk60MAmcGA6JoaVl4IGSAN0PuK31AkdS/bZCNqP/H6uihrfJOvHDAvqvEeDJ+ps8WumfEj/8dJLyVYalBrqOI+N7w6LzAGywZXjQyaHi+oERM3eF0Vq4dDCKvZKXl6ohhjHOQR8MQIDAQABo4GNMIGKMB0GA1UdDgQWBBTpcmpQpDUx+dUOkwICfjwb7aSguDAfBgNVHSMEGDAWgBTpcmpQpDUx+dUOkwICfjwb7aSguDAPBgNVHRMBAf8EBTADAQH/MDcGA1UdEQQwMC6CEWdvb2QuZXhhbXBsZS50ZXN0ghMqLmdvb2QuZXhhbXBsZS50ZXN0hwQKAAABMA0GCSqGSIb3DQEBCwUAA4IBAQCAE0VHGWsa6k/AXMCMUw9bHAG0PazCPGbm8QizKL9BLp69xI9lckPEL9zueCtkv3p9R7a6ytmoOfzqPlFx875cIoLDooic1TXvJ2NSsVLMAeFI7vzYPKHEz16/RhNMGd7FO7LYurZU1X7BvSHBsUJ09dlVtAN9hK2h+mMg35bORj8QdD4rOkQgNmWLZC5pjYd130KOU0qqb+2tdhpKgMi/iUWZ/ST3GIrgXqdw6o3wDuahZ6SlAIyzWuHZtA1o3m7IGodSFbY/6w7F79j+fF4kz5bwLE3zk3xfi9P22KVACoftPf5zJ+FkahRey+2tXE4JpanULhTcd0BaaaN7VbuJ</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>`
    const decoded = decodeSamlMetadata(xml)
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities[0].roles[0].signingCerts).toHaveLength(1)
  })

  it('skips KeyDescriptors marked use="encryption"', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      entityID="https://encryptonly.example.test/">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="encryption">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIIDmDCCAoCgAwIBAgIUQf+PjcchJeGRFb8hSPDDVnd96XYwDQYJKoZIhvcNAQELBQAwPjEaMBgGA1UEAwwRZ29vZC5leGFtcGxlLnRlc3QxEzARBgNVBAoMCkV4YW1wbGUgQ28xCzAJBgNVBAYTAlVTMB4XDTI2MDUxNjE2MjAyMFoXDTM2MDUxMzE2MjAyMFowPjEaMBgGA1UEAwwRZ29vZC5leGFtcGxlLnRlc3QxEzARBgNVBAoMCkV4YW1wbGUgQ28xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2WpxbJTiQx9DkETg3/lYk2/yjFcsxiU3d8vU7Es4kDYszvS8ftFS9rjVRJqMIhHsNZuOENR9PaIrugVJ0ZGmE1vvwLNQ8AmBLewgjbfNR/HKrNk+li0AdSOsnUYD4sYJZ5z+CQqw6mwZFjyHaO2wwT9+yps+CzHqc6MRomcl0kfcZYKNzNYbw2FdJxHoGKfn5NBhDRi2beZq9Hk60MAmcGA6JoaVl4IGSAN0PuK31AkdS/bZCNqP/H6uihrfJOvHDAvqvEeDJ+ps8WumfEj/8dJLyVYalBrqOI+N7w6LzAGywZXjQyaHi+oERM3eF0Vq4dDCKvZKXl6ohhjHOQR8MQIDAQABo4GNMIGKMB0GA1UdDgQWBBTpcmpQpDUx+dUOkwICfjwb7aSguDAfBgNVHSMEGDAWgBTpcmpQpDUx+dUOkwICfjwb7aSguDAPBgNVHRMBAf8EBTADAQH/MDcGA1UdEQQwMC6CEWdvb2QuZXhhbXBsZS50ZXN0ghMqLmdvb2QuZXhhbXBsZS50ZXN0hwQKAAABMA0GCSqGSIb3DQEBCwUAA4IBAQCAE0VHGWsa6k/AXMCMUw9bHAG0PazCPGbm8QizKL9BLp69xI9lckPEL9zueCtkv3p9R7a6ytmoOfzqPlFx875cIoLDooic1TXvJ2NSsVLMAeFI7vzYPKHEz16/RhNMGd7FO7LYurZU1X7BvSHBsUJ09dlVtAN9hK2h+mMg35bORj8QdD4rOkQgNmWLZC5pjYd130KOU0qqb+2tdhpKgMi/iUWZ/ST3GIrgXqdw6o3wDuahZ6SlAIyzWuHZtA1o3m7IGodSFbY/6w7F79j+fF4kz5bwLE3zk3xfi9P22KVACoftPf5zJ+FkahRey+2tXE4JpanULhTcd0BaaaN7VbuJ</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>`
    const decoded = decodeSamlMetadata(xml)
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities[0].roles[0].signingCerts).toHaveLength(0)
  })

  it('drops X509Certificate bodies that do not parse', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      entityID="https://badcert.example.test/">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>not-base64-cert</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>`
    const decoded = decodeSamlMetadata(xml)
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities[0].roles[0].signingCerts).toHaveLength(0)
  })

  it('accepts an EntityDescriptor with no roles', () => {
    const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      entityID="https://noroles.example.test/"></md:EntityDescriptor>`
    const decoded = decodeSamlMetadata(xml)
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities[0].roles).toEqual([])
  })

  it('accepts an EntitiesDescriptor wrapping a single EntityDescriptor (not wrapped in an array)', () => {
    const xml = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      Name="https://federation.example.test/">
      <md:EntityDescriptor entityID="https://single.example.test/">
        <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        </md:IDPSSODescriptor>
      </md:EntityDescriptor>
    </md:EntitiesDescriptor>`
    const decoded = decodeSamlMetadata(xml)
    if (!decoded) throw new Error('expected defined')
    expect(decoded.entities).toHaveLength(1)
    expect(decoded.entities[0].entityId).toBe('https://single.example.test/')
  })
})
