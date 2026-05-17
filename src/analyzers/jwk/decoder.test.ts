import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeJwkInput, looksLikeJwkJson } from './decoder'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

describe('looksLikeJwkJson', () => {
  it('accepts a single-key JWK', () => {
    expect(looksLikeJwkJson(read('rsa-public.json'))).toBe(true)
  })
  it('accepts a JWKS document', () => {
    expect(looksLikeJwkJson(read('jwks.json'))).toBe(true)
  })
  it('rejects non-JSON', () => {
    expect(looksLikeJwkJson('hello')).toBe(false)
  })
  it('rejects JSON without kty/keys', () => {
    expect(looksLikeJwkJson('{"foo":1}')).toBe(false)
  })
})

describe('decodeJwkInput', () => {
  it('decodes an RSA public JWK', () => {
    const decoded = decodeJwkInput(read('rsa-public.json'))
    expect(decoded.kind).toBe('jwk')
    if (decoded.kind !== 'jwk') throw new Error('type narrowed')
    expect(decoded.key.kty).toBe('RSA')
    expect(decoded.key.keySizeBits).toBe(2048)
    expect(decoded.key.hasPrivateMaterial).toBe(false)
  })

  it('decodes an EC public JWK', () => {
    const decoded = decodeJwkInput(read('ec-public.json'))
    if (decoded.kind !== 'jwk') throw new Error('expected jwk')
    expect(decoded.key.kty).toBe('EC')
    expect(decoded.key.curve).toBe('P-256')
  })

  it('detects private material in an EC private JWK', () => {
    const decoded = decodeJwkInput(read('ec-private.json'))
    if (decoded.kind !== 'jwk') throw new Error('expected jwk')
    expect(decoded.key.hasPrivateMaterial).toBe(true)
  })

  it('decodes a JWKS', () => {
    const decoded = decodeJwkInput(read('jwks.json'))
    expect(decoded.kind).toBe('jwks')
    if (decoded.kind !== 'jwks') throw new Error('expected jwks')
    expect(decoded.keys).toHaveLength(2)
  })

  it('throws on non-JSON input', () => {
    expect(() => decodeJwkInput('hello')).toThrow(/does not look like JSON/)
  })

  it('throws on invalid JSON', () => {
    expect(() => decodeJwkInput('{not json')).toThrow(/Invalid JSON/)
  })

  it('throws on JSON that is neither JWK nor JWKS', () => {
    expect(() => decodeJwkInput('{"foo":"bar"}')).toThrow(/neither a JWK/)
  })

  it('treats arrays and primitives as non-objects', () => {
    expect(() => decodeJwkInput('[]')).toThrow()
  })

  it('handles oct keys with k', () => {
    const oct = JSON.stringify({ kty: 'oct', k: 'YWJjZGVmZ2hpamtsbW5vcA' })
    const decoded = decodeJwkInput(oct)
    if (decoded.kind !== 'jwk') throw new Error('expected jwk')
    expect(decoded.key.keySizeBits).toBe(128)
    expect(decoded.key.hasPrivateMaterial).toBe(true)
  })

  it('handles unknown kty gracefully', () => {
    const decoded = decodeJwkInput(JSON.stringify({ kty: 'XYZ' }))
    if (decoded.kind !== 'jwk') throw new Error('expected jwk')
    expect(decoded.key.kty).toBe('XYZ')
  })
})
