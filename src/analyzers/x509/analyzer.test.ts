import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { X509Analyzer } from './analyzer'

const FIX_DIR = join(__dirname, 'fixtures')
const pem = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')
const bin = (n: string) => readFileSync(join(FIX_DIR, n))
const NOW = Date.UTC(2026, 0, 1)

describe('X509Analyzer', () => {
  const analyzer = new X509Analyzer({ now: NOW })

  it('detects a PEM block', () => {
    const text = pem('good.pem')
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBe(0)
  })

  it('does not match arbitrary text', () => {
    expect(analyzer.detect('plain text')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces a certificate section with the canonical rows', () => {
    const [m] = analyzer.detect(pem('good.pem'))
    const result = analyzer.analyze(m)
    expect(result.analyzerId).toBe('x509')
    expect(result.sections[0].id).toBe('certificate')
    const keys = result.sections[0].rows.map((r) => r.key)
    for (const k of ['subject', 'issuer', 'validFrom', 'validTo', 'keyAlgorithm', 'signatureAlgorithm', 'fingerprint256']) {
      expect(keys).toContain(k)
    }
    expect(keys).toContain('subjectAltNames')
    expect(keys).toContain('selfSigned')
  })

  it('finds findings for a weak-key cert', () => {
    const [m] = analyzer.detect(pem('weak-key.pem'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'x509.key.weakRsa')).toBeDefined()
  })

  it('finds findings for a SHA-1 cert', () => {
    const [m] = analyzer.detect(pem('sha1.pem'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'x509.signature.weakAlgorithm')).toBeDefined()
  })

  describe('base64-DER (no PEM armor)', () => {
    // The body of a .cer/.crt file is the raw DER cert, base64 encoded.
    const derBase64 = bin('good.der').toString('base64')

    it('detects base64-DER content (single match spanning the full text)', () => {
      const matches = analyzer.detect(derBase64)
      expect(matches).toHaveLength(1)
      expect(matches[0].range?.start).toBe(0)
      expect(matches[0].range?.end).toBe(derBase64.length)
      expect(matches[0].text.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true)
    })

    it('analyzes a DER match to the same certificate data as the PEM form', () => {
      const [derMatch] = analyzer.detect(derBase64)
      const [pemMatch] = analyzer.detect(pem('good.pem'))
      const derResult = analyzer.analyze(derMatch)
      const pemResult = analyzer.analyze(pemMatch)

      const fpRow = (r: typeof derResult) =>
        r.sections[0].rows.find((row) => row.key === 'fingerprint256')?.value
      expect(fpRow(derResult)).toBe(fpRow(pemResult))
      expect(derResult.kind).toBe('CA (DER)')
      expect(pemResult.kind).toBe('CA')
    })

    it('adds an x509.encoding.der info finding for DER matches', () => {
      const [m] = analyzer.detect(derBase64)
      const result = analyzer.analyze(m)
      const der = result.findings.find((f) => f.id === 'x509.encoding.der')
      expect(der).toBeDefined()
      expect(der?.severity).toBe('info')
    })

    it('PEM matches do NOT carry the DER encoding finding', () => {
      const [m] = analyzer.detect(pem('good.pem'))
      const result = analyzer.analyze(m)
      expect(result.findings.find((f) => f.id === 'x509.encoding.der')).toBeUndefined()
      // Encoding row reports "PEM" for PEM inputs.
      expect(
        result.sections[0].rows.find((r) => r.key === 'encoding')?.value
      ).toBe('PEM')
    })

    it('still produces standard rows (subject/issuer/sigalg/fp) for DER input', () => {
      const [m] = analyzer.detect(derBase64)
      const result = analyzer.analyze(m)
      const keys = result.sections[0].rows.map((r) => r.key)
      for (const k of [
        'subject',
        'issuer',
        'validFrom',
        'validTo',
        'keyAlgorithm',
        'signatureAlgorithm',
        'fingerprint256',
        'encoding',
      ]) {
        expect(keys).toContain(k)
      }
    })

    it('does not match arbitrary short base64-like text', () => {
      expect(analyzer.detect('SGVsbG8gV29ybGQ=')).toEqual([])
    })
  })
})
