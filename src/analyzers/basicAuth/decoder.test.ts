import { describe, expect, it } from 'vitest'
import { decodeBasic } from './decoder'

function b64(s: string): string {
  return Buffer.from(s, 'utf-8').toString('base64')
}

describe('decodeBasic', () => {
  it('decodes a typical Basic credential', () => {
    expect(decodeBasic(b64('alice:wonderland'))).toEqual({ user: 'alice', password: 'wonderland' })
  })

  it('preserves a password that contains a colon', () => {
    // RFC 7617: only the FIRST colon is the user/password separator.
    const encoded = b64('admin:s3cret:with:colons')
    expect(decodeBasic(encoded)).toEqual({ user: 'admin', password: 's3cret:with:colons' })
  })

  it('preserves a password that contains spaces and punctuation', () => {
    const encoded = b64('bob:hello world!')
    expect(decodeBasic(encoded)).toEqual({ user: 'bob', password: 'hello world!' })
  })

  it('handles unicode usernames and passwords', () => {
    const encoded = b64('zoë:pässwörd')
    expect(decodeBasic(encoded)).toEqual({ user: 'zoë', password: 'pässwörd' })
  })

  it('tolerates trailing whitespace, CR and LF on the input', () => {
    const encoded = `${b64('alice:wonderland')}   \n`
    expect(decodeBasic(encoded)).toEqual({ user: 'alice', password: 'wonderland' })
  })

  it('tolerates a trailing newline that came from inside the encoded blob', () => {
    const encoded = b64('alice:wonderland\n')
    expect(decodeBasic(encoded)).toEqual({ user: 'alice', password: 'wonderland' })
  })

  it('accepts URL-safe base64 (`-` / `_`) in addition to the standard alphabet', () => {
    // `?>?>` encodes to `Pz4_Pj4=` in URL-safe form (`/` → `_`).
    const standard = Buffer.from('user:p?>?>').toString('base64')
    const urlSafe = standard.replace(/\+/g, '-').replace(/\//g, '_')
    expect(decodeBasic(urlSafe)).toEqual({ user: 'user', password: 'p?>?>' })
  })

  it('accepts base64 without padding', () => {
    const padded = b64('a:b') // 'YTpi'
    const noPad = padded.replace(/=+$/, '')
    expect(decodeBasic(noPad)).toEqual({ user: 'a', password: 'b' })
  })

  it('returns undefined for non-string input', () => {
    expect(decodeBasic(undefined as unknown as string)).toBeUndefined()
    expect(decodeBasic(null as unknown as string)).toBeUndefined()
    expect(decodeBasic(123 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for empty / whitespace-only input', () => {
    expect(decodeBasic('')).toBeUndefined()
    expect(decodeBasic('   ')).toBeUndefined()
    expect(decodeBasic('\n\r')).toBeUndefined()
  })

  it('returns undefined when the input contains non-base64 characters', () => {
    expect(decodeBasic('not base64!')).toBeUndefined()
    expect(decodeBasic('hello world')).toBeUndefined()
  })

  it('returns undefined when base64 length mod 4 === 1 (impossible padding)', () => {
    // 'A' alone — base64 decodes are invalid at length 1.
    expect(decodeBasic('A')).toBeUndefined()
    // 5 chars also yields mod 1.
    expect(decodeBasic('YWxpY')).toBeUndefined()
  })

  it('returns undefined when decoded bytes are not valid UTF-8', () => {
    // Single byte 0xC3 starts a 2-byte UTF-8 sequence but no continuation follows.
    const broken = Buffer.from([0xc3]).toString('base64')
    expect(decodeBasic(broken)).toBeUndefined()
  })

  it('returns undefined when decoded text has no colon', () => {
    expect(decodeBasic(b64('justastring'))).toBeUndefined()
    expect(decodeBasic(b64('no-colon-here'))).toBeUndefined()
  })

  it('returns undefined when the username portion is empty', () => {
    expect(decodeBasic(b64(':password'))).toBeUndefined()
  })

  it('returns undefined when the password portion is empty', () => {
    expect(decodeBasic(b64('username:'))).toBeUndefined()
  })

  it('returns undefined when both username and password are empty', () => {
    expect(decodeBasic(b64(':'))).toBeUndefined()
  })

  it('returns undefined for atob-throwing input that nevertheless matches the alphabet check', () => {
    // The alphabet check would let this through; padding is fine; atob throws.
    // Construct a malformed string by re-encoding with non-canonical padding.
    // (`====` is the empty string in base64 — decodes to length 0, no colon.)
    expect(decodeBasic('====')).toBeUndefined()
  })
})
