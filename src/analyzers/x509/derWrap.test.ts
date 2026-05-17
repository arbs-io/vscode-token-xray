import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { tryWrapDerAsPem } from './derWrap'
import { decodeX509 } from './decoder'

const FIX_DIR = join(__dirname, 'fixtures')
const goodDerBytes = readFileSync(join(FIX_DIR, 'good.der'))
const goodDerBase64 = goodDerBytes.toString('base64')
const goodPem = readFileSync(join(FIX_DIR, 'good.pem'), 'utf8')

describe('tryWrapDerAsPem', () => {
  it('wraps a valid base64-DER blob when filename ends in .cer', () => {
    const out = tryWrapDerAsPem(goodDerBase64, 'cert.cer')
    expect(out).toBeDefined()
    expect(out!).toContain('-----BEGIN CERTIFICATE-----')
    expect(out!).toContain('-----END CERTIFICATE-----')
    // The wrapped form must decode to the same subject as the original PEM.
    const wrappedDecoded = decodeX509(out!)
    const originalDecoded = decodeX509(goodPem)
    expect(wrappedDecoded.fingerprint256).toBe(originalDecoded.fingerprint256)
  })

  it('wraps when filename ends in .crt (case-insensitive)', () => {
    expect(tryWrapDerAsPem(goodDerBase64, 'EXPORT.CRT')).toBeDefined()
  })

  it('wraps when filename ends in .der', () => {
    expect(tryWrapDerAsPem(goodDerBase64, 'cert.der')).toBeDefined()
  })

  it('wraps long unlabelled base64 (no filename, ≥1000 chars, valid DER bytes)', () => {
    expect(goodDerBase64.length).toBeGreaterThanOrEqual(1000)
    expect(tryWrapDerAsPem(goodDerBase64)).toBeDefined()
  })

  it('tolerates whitespace inside the base64 body', () => {
    // 64-char-wrapped form, similar to what a `.cer` file from openssl emits.
    const wrapped = goodDerBase64.match(/.{1,64}/g)!.join('\n')
    expect(tryWrapDerAsPem(wrapped, 'cert.cer')).toBeDefined()
  })

  it('returns undefined when text already contains PEM armor', () => {
    expect(tryWrapDerAsPem(goodPem, 'cert.cer')).toBeUndefined()
  })

  it('returns undefined when text is empty', () => {
    expect(tryWrapDerAsPem('')).toBeUndefined()
    expect(tryWrapDerAsPem('   \n  ')).toBeUndefined()
  })

  it('returns undefined for short unlabelled base64 (below the 1000-char threshold)', () => {
    const short = goodDerBase64.slice(0, 200)
    expect(tryWrapDerAsPem(short)).toBeUndefined()
  })

  it('returns undefined when filename has the right suffix but text is not base64', () => {
    expect(tryWrapDerAsPem('this is not base64 at all !!', 'cert.cer')).toBeUndefined()
  })

  it('returns undefined when base64 length is not a multiple of 4', () => {
    // Drop the last padding char so the length is no longer mod-4.
    const odd = goodDerBase64.slice(0, goodDerBase64.length - 1)
    expect(tryWrapDerAsPem(odd, 'cert.cer')).toBeUndefined()
  })

  it('returns undefined when decoded bytes do not start with 0x30 0x82', () => {
    // Random base64 that is long enough but decodes to non-DER bytes.
    const bogus = 'A'.repeat(2000)
    expect(tryWrapDerAsPem(bogus, 'cert.cer')).toBeUndefined()
  })

  it('returns undefined when decoded length does not match the declared SEQUENCE length', () => {
    // Truncate the real DER blob by ~50 bytes and re-encode → length mismatch.
    const truncated = goodDerBytes.subarray(0, goodDerBytes.length - 50).toString('base64')
    expect(tryWrapDerAsPem(truncated, 'cert.cer')).toBeUndefined()
  })

  it('returns undefined for unrelated filenames with sub-threshold content', () => {
    // 999 char base64 with a wrong filename — both gates fail.
    const sub = 'A'.repeat(996) // multiple of 4
    expect(tryWrapDerAsPem(sub, 'data.txt')).toBeUndefined()
  })
})
