import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeX509, extractCertificateBlocks } from './decoder'

const FIX_DIR = join(__dirname, 'fixtures')

function pem(name: string): string {
  return readFileSync(join(FIX_DIR, name), 'utf8')
}

describe('extractCertificateBlocks', () => {
  it('finds a single PEM block', () => {
    const blocks = extractCertificateBlocks(pem('good.pem'))
    expect(blocks).toHaveLength(1)
    expect(blocks[0].start).toBe(0)
  })

  it('finds multiple PEM blocks', () => {
    const text = `${pem('good.pem')}\nSome text\n${pem('weak-key.pem')}`
    expect(extractCertificateBlocks(text)).toHaveLength(2)
  })

  it('returns empty for input without certificates', () => {
    expect(extractCertificateBlocks('no cert here')).toEqual([])
  })

  it('returns empty for empty input', () => {
    expect(extractCertificateBlocks('')).toEqual([])
  })
})

describe('decodeX509', () => {
  it('extracts subject/issuer/dates/key/signature for a healthy RSA-2048 SHA-256 cert', () => {
    const result = decodeX509(pem('good.pem'))
    expect(result.subject).toContain('good.example.test')
    expect(result.issuer).toContain('good.example.test')
    expect(result.selfSigned).toBe(true)
    expect(result.keyAlgorithm).toBe('rsa')
    expect(result.keyDetails).toBe('RSA-2048')
    expect(result.signatureAlgorithm).toBe('sha256WithRSAEncryption')
    expect(result.subjectAltNames.length).toBeGreaterThanOrEqual(2)
    expect(result.fingerprint256).toMatch(/^[0-9A-F:]+$/)
  })

  it('detects RSA-1024 key length', () => {
    const result = decodeX509(pem('weak-key.pem'))
    expect(result.keyDetails).toBe('RSA-1024')
  })

  it('detects SHA-1 signature algorithm', () => {
    const result = decodeX509(pem('sha1.pem'))
    expect(result.signatureAlgorithm).toBe('sha1WithRSAEncryption')
  })

  it('parses expired-cert validity dates', () => {
    const result = decodeX509(pem('expired.pem'))
    expect(Date.parse(result.validTo)).toBeLessThan(Date.now())
  })
})
