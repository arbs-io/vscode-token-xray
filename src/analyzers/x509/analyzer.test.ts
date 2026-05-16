import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { X509Analyzer } from './analyzer'

const FIX_DIR = join(__dirname, 'fixtures')
const pem = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')
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
})
