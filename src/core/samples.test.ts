import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createDefaultRegistry } from './defaultRegistry'
import { scanDocument } from './scanDocument'

const SAMPLE_DIR = join(__dirname, '..', '..', 'sample')

function read(file: string): string {
  return readFileSync(join(SAMPLE_DIR, file), 'utf8')
}

describe('sample files exercise the analyzers', () => {
  const registry = createDefaultRegistry()
  const files = readdirSync(SAMPLE_DIR).filter((f) => !f.startsWith('.') && f !== 'README.md')

  it('exists', () => {
    expect(files.length).toBeGreaterThan(0)
  })

  it.each(
    files.filter((f) => f.endsWith('.jwt'))
  )('JWT sample %s is detected', (file) => {
    const hits = scanDocument(read(file), registry)
    expect(hits.some((h) => h.analyzerId === 'jwt')).toBe(true)
  })

  it.each([
    'saml-response.xml',
    'saml-response.b64',
    'saml-response.redirect',
    'saml-response-unsigned.xml',
    'saml-response-encrypted.xml',
  ])('SAML sample %s is detected', (file) => {
    const hits = scanDocument(read(file), registry)
    expect(hits.some((h) => h.analyzerId === 'saml')).toBe(true)
  })

  it.each([
    'cert-good.pem',
    'cert-weak-key.pem',
    'cert-sha1.pem',
    'cert-expired.pem',
  ])('X.509 sample %s is detected', (file) => {
    const hits = scanDocument(read(file), registry)
    expect(hits.some((h) => h.analyzerId === 'x509')).toBe(true)
  })

  it.each([
    'jwk-rsa-public.json',
    'jwk-rsa-weak.json',
    'jwk-ec-public.json',
    'jwk-ec-private.json',
    'jwks.json',
  ])('JWK sample %s is detected', (file) => {
    const hits = scanDocument(read(file), registry)
    expect(hits.some((h) => h.analyzerId === 'jwk')).toBe(true)
  })

  it('oauth-tokens.txt produces multiple oauth-tagged hits (one per vendor pattern)', () => {
    const hits = scanDocument(read('oauth-tokens.txt'), registry)
    const oauthHits = hits.filter((h) => h.analyzerId === 'oauth')
    expect(oauthHits.length).toBeGreaterThanOrEqual(10)
  })

  it('cookies.http produces multiple cookie-tagged hits', () => {
    const hits = scanDocument(read('cookies.http'), registry)
    const cookieHits = hits.filter((h) => h.analyzerId === 'cookie')
    expect(cookieHits.length).toBeGreaterThanOrEqual(8)
  })

  it('secrets.txt produces secret-tagged hits across all supported vendors', () => {
    const hits = scanDocument(read('secrets.txt'), registry)
    const secretHits = hits.filter((h) => h.analyzerId === 'secret')
    // PEM x2 + AWS x4 + GCP x5 + Okta x3 + Cloudflare x5 + Auth0 x3 + SailPoint x3 + Azure x6 + GitHub x3 ≈ 34
    expect(secretHits.length).toBeGreaterThanOrEqual(31)
  })
})
