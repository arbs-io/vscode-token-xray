import { describe, expect, it } from 'vitest'
import { detectSignatureAlgorithm, isWeakSignatureAlgorithm, SIG_ALG_TABLE } from './sigalg'

describe('detectSignatureAlgorithm', () => {
  it('finds sha256WithRSAEncryption when present', () => {
    const entry = SIG_ALG_TABLE.find((e) => e.name === 'sha256WithRSAEncryption')!
    const buf = Buffer.from([0xff, ...entry.oidBytes, 0x00])
    expect(detectSignatureAlgorithm(buf)).toBe('sha256WithRSAEncryption')
  })

  it('returns "unknown" when no known OID is present', () => {
    expect(detectSignatureAlgorithm(Buffer.from([0x01, 0x02, 0x03]))).toBe('unknown')
  })

  it('returns "unknown" for empty input', () => {
    expect(detectSignatureAlgorithm(Buffer.alloc(0))).toBe('unknown')
  })
})

describe('isWeakSignatureAlgorithm', () => {
  it('flags SHA-1 and MD5 variants', () => {
    expect(isWeakSignatureAlgorithm('sha1WithRSAEncryption')).toBe(true)
    expect(isWeakSignatureAlgorithm('md5WithRSAEncryption')).toBe(true)
    expect(isWeakSignatureAlgorithm('ecdsa-with-SHA1')).toBe(true)
  })

  it('accepts SHA-256+ as not weak', () => {
    expect(isWeakSignatureAlgorithm('sha256WithRSAEncryption')).toBe(false)
    expect(isWeakSignatureAlgorithm('ecdsa-with-SHA256')).toBe(false)
    expect(isWeakSignatureAlgorithm('ed25519')).toBe(false)
  })
})
