import { detectJwtKind } from './decoder'
import { JwtKind } from './types'

export interface ParsedJwtToken {
  line: number
  startCharacter: number
  length: number
  tokenType: JwtSemanticTokenType
}

export type JwtSemanticTokenType =
  | 'jwt_joseHeader'
  | 'jwt_claimsSet'
  | 'jwt_signature'
  | 'jwt_encryptedKey'
  | 'jwt_iv'
  | 'jwt_ciphertext'
  | 'jwt_authTag'

const JWS_LEGEND: JwtSemanticTokenType[] = ['jwt_joseHeader', 'jwt_claimsSet', 'jwt_signature']
const JWE_LEGEND: JwtSemanticTokenType[] = [
  'jwt_joseHeader',
  'jwt_encryptedKey',
  'jwt_iv',
  'jwt_ciphertext',
  'jwt_authTag',
]

export const ALL_JWT_SEMANTIC_TOKEN_TYPES: JwtSemanticTokenType[] = [
  ...JWS_LEGEND,
  'jwt_encryptedKey',
  'jwt_iv',
  'jwt_ciphertext',
  'jwt_authTag',
]

function legendFor(kind: JwtKind): JwtSemanticTokenType[] | null {
  if (kind === 'JWS') return JWS_LEGEND
  if (kind === 'JWE') return JWE_LEGEND
  return null
}

export function parseJwtTokensInLine(line: string, lineNumber: number): ParsedJwtToken[] {
  const trimmed = line.trim()
  if (trimmed.length === 0) return []
  const kind = detectJwtKind(trimmed)
  const legend = legendFor(kind)
  if (!legend) return []

  const segments = trimmed.split('.')
  if (segments.length !== legend.length) return []

  const result: ParsedJwtToken[] = []
  let cursor = 0
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]
    const start = line.indexOf(segment, cursor)
    if (start < 0) return []
    result.push({
      line: lineNumber,
      startCharacter: start,
      length: segment.length,
      tokenType: legend[i],
    })
    cursor = start + segment.length + 1
  }
  return result
}

export function parseJwtTokens(text: string): ParsedJwtToken[] {
  const lines = text.split(/\r\n|\r|\n/)
  const out: ParsedJwtToken[] = []
  for (let i = 0; i < lines.length; i++) {
    out.push(...parseJwtTokensInLine(lines[i], i))
  }
  return out
}
