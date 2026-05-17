import { describe, expect, it } from 'vitest'
import { parseJwtTokens, parseJwtTokensInLine } from './semanticParser'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
}

const JWS = `${b64u({ alg: 'RS256' })}.${b64u({ sub: 'a' })}.sig`
const JWE = `${b64u({ alg: 'RSA-OAEP', enc: 'A256GCM' })}.encKey.iv.ct.tag`

describe('parseJwtTokensInLine', () => {
  it('parses a JWS into three tokens with JWS legend', () => {
    const tokens = parseJwtTokensInLine(JWS, 0)
    expect(tokens.map((t) => t.tokenType)).toEqual([
      'jwt_joseHeader',
      'jwt_claimsSet',
      'jwt_signature',
    ])
    expect(tokens[0].startCharacter).toBe(0)
    expect(tokens[2].startCharacter).toBeGreaterThan(0)
  })

  it('parses a JWE into five tokens with JWE legend', () => {
    const tokens = parseJwtTokensInLine(JWE, 3)
    expect(tokens.map((t) => t.tokenType)).toEqual([
      'jwt_joseHeader',
      'jwt_encryptedKey',
      'jwt_iv',
      'jwt_ciphertext',
      'jwt_authTag',
    ])
    expect(tokens.every((t) => t.line === 3)).toBe(true)
  })

  it('returns nothing for malformed tokens', () => {
    expect(parseJwtTokensInLine('has spaces.in.it', 0)).toEqual([])
    expect(parseJwtTokensInLine('a.b', 0)).toEqual([])
    expect(parseJwtTokensInLine('a.b.c.d', 0)).toEqual([])
    expect(parseJwtTokensInLine('', 0)).toEqual([])
  })

  it('handles tokens with leading whitespace', () => {
    const tokens = parseJwtTokensInLine(`   ${JWS}`, 0)
    expect(tokens).toHaveLength(3)
    expect(tokens[0].startCharacter).toBe(3)
  })
})

describe('parseJwtTokens', () => {
  it('parses multi-line input with mixed token kinds', () => {
    const text = `${JWS}\n${JWE}\nnot a token`
    const tokens = parseJwtTokens(text)
    expect(tokens.filter((t) => t.line === 0)).toHaveLength(3)
    expect(tokens.filter((t) => t.line === 1)).toHaveLength(5)
    expect(tokens.filter((t) => t.line === 2)).toHaveLength(0)
  })

  it('handles CRLF line endings', () => {
    const text = `${JWS}\r\n${JWE}`
    const tokens = parseJwtTokens(text)
    expect(tokens.filter((t) => t.line === 0)).toHaveLength(3)
    expect(tokens.filter((t) => t.line === 1)).toHaveLength(5)
  })

  it('returns empty array for empty input', () => {
    expect(parseJwtTokens('')).toEqual([])
  })
})
