import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { CsrAnalyzer } from './analyzer'

const FIX_DIR = join(__dirname, 'fixtures')
const pem = (name: string): string => readFileSync(join(FIX_DIR, name), 'utf8')

describe('CsrAnalyzer', () => {
  const analyzer = new CsrAnalyzer()

  it('exposes id "csr" and a human name', () => {
    expect(analyzer.id).toBe('csr')
    expect(analyzer.name).toBe('Certificate Signing Request')
  })

  it('detects a CSR PEM block with byte range', () => {
    const text = pem('good.pem')
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBe(0)
    expect(matches[0].range?.end).toBeGreaterThan(0)
    expect(matches[0].text).toContain('-----BEGIN CERTIFICATE REQUEST-----')
  })

  it('does not match arbitrary text', () => {
    expect(analyzer.detect('')).toEqual([])
    expect(analyzer.detect('plain text without any csr')).toEqual([])
  })

  it('produces a Subject & Key section with subject, algorithm, key size, and SANs rows', () => {
    const [m] = analyzer.detect(pem('good.pem'))
    const result = analyzer.analyze(m)
    expect(result.analyzerId).toBe('csr')
    expect(result.kind).toBe('PKCS#10 CSR')
    expect(result.sections).toHaveLength(1)
    expect(result.sections[0].id).toBe('subjectKey')
    expect(result.sections[0].title).toBe('Subject & Key')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('subject')
    expect(keys).toContain('algorithm')
    expect(keys).toContain('keySize')
    expect(keys).toContain('subjectAltNames')
    const sanRow = result.sections[0].rows.find((r) => r.key === 'subjectAltNames')
    expect(String(sanRow?.value)).toContain('DNS:good.example.test')
  })

  it('reports algorithm value "RSA" for RSA CSRs', () => {
    const [m] = analyzer.detect(pem('good.pem'))
    const result = analyzer.analyze(m)
    const algoRow = result.sections[0].rows.find((r) => r.key === 'algorithm')
    expect(algoRow?.value).toBe('RSA')
  })

  it('reports keySize as "2048 bits" for a healthy RSA CSR', () => {
    const [m] = analyzer.detect(pem('good.pem'))
    const result = analyzer.analyze(m)
    const sizeRow = result.sections[0].rows.find((r) => r.key === 'keySize')
    expect(sizeRow?.value).toBe('2048 bits')
  })

  it('emits csr.key.weakRsa for a 1024-bit CSR', () => {
    const [m] = analyzer.detect(pem('weak-key.pem'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'csr.key.weakRsa')).toBeDefined()
  })

  it('emits csr.san.missing for a CSR without SAN', () => {
    const [m] = analyzer.detect(pem('no-san.pem'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'csr.san.missing')).toBeDefined()
    const sanRow = result.sections[0].rows.find((r) => r.key === 'subjectAltNames')
    expect(sanRow?.value).toBe('(none requested)')
  })

  it('emits csr.parse.failed and "(malformed)" kind for an unparseable PEM block', () => {
    const malformed =
      '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----'
    const [m] = analyzer.detect(malformed)
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('PKCS#10 CSR (malformed)')
    expect(result.findings.find((f) => f.id === 'csr.parse.failed')).toBeDefined()
    expect(result.sections[0].rows[0].key).toBe('status')
  })

  it('PEM matches do not carry parse-failed findings on good input', () => {
    const [m] = analyzer.detect(pem('good.pem'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'csr.parse.failed')).toBeUndefined()
  })

  describe('EC CSR', () => {
    it('reports algorithm as "EC (P-256)" and surfaces a curve row instead of keySize', () => {
      const [m] = analyzer.detect(pem('ec.pem'))
      const result = analyzer.analyze(m)
      const algoRow = result.sections[0].rows.find((r) => r.key === 'algorithm')
      const curveRow = result.sections[0].rows.find((r) => r.key === 'curve')
      const sizeRow = result.sections[0].rows.find((r) => r.key === 'keySize')
      expect(algoRow?.value).toBe('EC (P-256)')
      expect(curveRow?.value).toBe('P-256')
      expect(sizeRow).toBeUndefined()
    })

    it('does not emit csr.key.weakRsa for an EC key (regardless of curve)', () => {
      const [m] = analyzer.detect(pem('ec.pem'))
      const result = analyzer.analyze(m)
      expect(result.findings.find((f) => f.id === 'csr.key.weakRsa')).toBeUndefined()
    })
  })
})
