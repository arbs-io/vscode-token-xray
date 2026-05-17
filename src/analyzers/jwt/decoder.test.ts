import { describe, expect, it } from 'vitest'
import { decodeJwt, detectJwtKind } from './decoder'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function jws(header: object, payload: object, sig = 'sig'): string {
  return `${b64u(header)}.${b64u(payload)}.${sig}`
}

describe('detectJwtKind', () => {
  it('identifies a 3-segment JWS', () => {
    expect(detectJwtKind(jws({ alg: 'RS256' }, { sub: 'x' }))).toBe('JWS')
  })

  it('identifies a 5-segment JWE', () => {
    expect(detectJwtKind('a.b.c.d.e')).toBe('JWE')
  })

  it('returns unknown for malformed tokens', () => {
    expect(detectJwtKind('a.b')).toBe('unknown')
    expect(detectJwtKind('not a token')).toBe('unknown')
  })
})

describe('decodeJwt', () => {
  it('decodes header and claimset of a valid JWS', () => {
    const token = jws({ alg: 'RS256', kid: 'k1' }, { sub: 'alice', iss: 'me' })
    const decoded = decodeJwt(token)
    expect(decoded.kind).toBe('JWS')
    expect(decoded.header.alg).toBe('RS256')
    expect(decoded.header.kid).toBe('k1')
    expect(decoded.payload?.sub).toBe('alice')
    expect(decoded.payload?.iss).toBe('me')
    expect(decoded.signature).toBe('sig')
  })

  it('decodes a JWE: header only, no payload', () => {
    const header = b64u({ alg: 'RSA-OAEP', enc: 'A256GCM' })
    const token = `${header}.encKey.iv.ct.tag`
    const decoded = decodeJwt(token)
    expect(decoded.kind).toBe('JWE')
    expect(decoded.header.enc).toBe('A256GCM')
    expect(decoded.payload).toBeUndefined()
  })

  it('throws on invalid input type', () => {
    expect(() => decodeJwt('')).toThrow(/Invalid token/)
    expect(() => decodeJwt(undefined as unknown as string)).toThrow()
  })

  it('throws on malformed JOSE header JSON', () => {
    const token = `notbase64.${b64u({ sub: 'x' })}.sig`
    expect(() => decodeJwt(token)).toThrow(/Invalid JOSE header/)
  })

  it('throws on malformed claimset JSON', () => {
    const token = `${b64u({ alg: 'none' })}.notbase64.sig`
    expect(() => decodeJwt(token)).toThrow(/Invalid claimset/)
  })

  it('handles tokens with empty signature segment (alg:none)', () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const decoded = decodeJwt(token)
    expect(decoded.kind).toBe('JWS')
    expect(decoded.signature).toBe('')
  })
})
