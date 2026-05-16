import { base64UrlDecode } from '../../core/base64url'
import { DecodedJwt, JoseHeader, JwtClaimsSet, JwtKind } from './types'

const JWS_REGEX = /^[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*$/
const JWE_REGEX = /^[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+$/

export function detectJwtKind(token: string): JwtKind {
  const segments = token.split('.')
  if (segments.length === 5 && JWE_REGEX.test(token)) return 'JWE'
  if (segments.length === 3 && JWS_REGEX.test(token)) return 'JWS'
  return 'unknown'
}

export function decodeJwt(token: string): DecodedJwt {
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error('Invalid token: expected non-empty string')
  }
  const segments = token.split('.')
  const kind = detectJwtKind(token)

  let header: JoseHeader
  try {
    header = JSON.parse(base64UrlDecode(segments[0])) as JoseHeader
  } catch (e) {
    throw new Error(`Invalid JOSE header: ${(e as Error).message}`)
  }

  if (kind === 'JWE') {
    return { kind, header, segments, raw: token }
  }

  let payload: JwtClaimsSet | undefined
  if (segments.length >= 2 && segments[1].length > 0) {
    try {
      payload = JSON.parse(base64UrlDecode(segments[1])) as JwtClaimsSet
    } catch (e) {
      throw new Error(`Invalid claimset: ${(e as Error).message}`)
    }
  }

  return {
    kind,
    header,
    payload,
    signature: segments[2],
    segments,
    raw: token,
  }
}
