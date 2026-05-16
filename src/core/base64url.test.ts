import { describe, expect, it } from 'vitest'
import { base64UrlDecode, base64UrlDecodeBytes } from './base64url'

describe('base64UrlDecode', () => {
  it('decodes standard base64url strings', () => {
    expect(base64UrlDecode('aGVsbG8')).toBe('hello')
  })

  it('decodes unicode payloads via percent-encoding fallback', () => {
    const text = 'café'
    const encoded = Buffer.from(text, 'utf8')
      .toString('base64')
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
    expect(base64UrlDecode(encoded)).toBe(text)
  })

  it('handles missing padding (length % 4 == 2)', () => {
    expect(base64UrlDecode('YQ')).toBe('a')
  })

  it('handles missing padding (length % 4 == 3)', () => {
    expect(base64UrlDecode('YWI')).toBe('ab')
  })

  it('replaces - and _ with + and /', () => {
    const raw = '+/+/'
    const urlSafe = '-_-_'
    expect(base64UrlDecode(urlSafe)).toBe(base64UrlDecode(raw))
  })

  it('throws on impossible length', () => {
    expect(() => base64UrlDecode('a')).toThrow(/invalid base64url/)
  })
})

describe('base64UrlDecodeBytes', () => {
  it('returns a Uint8Array of decoded bytes', () => {
    const bytes = base64UrlDecodeBytes('AAEC')
    expect(Array.from(bytes)).toEqual([0, 1, 2])
  })

  it('throws on impossible length', () => {
    expect(() => base64UrlDecodeBytes('a')).toThrow(/invalid base64url/)
  })
})
