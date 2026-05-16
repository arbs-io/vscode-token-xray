export interface JoseHeader {
  alg?: string
  typ?: string
  cty?: string
  kid?: string
  jku?: string
  jwk?: unknown
  x5u?: string
  x5c?: string[]
  x5t?: string
  'x5t#S256'?: string
  crit?: string[]
  enc?: string
  [key: string]: unknown
}

export interface JwtClaimsSet {
  iss?: string
  sub?: string
  aud?: string | string[]
  exp?: number
  nbf?: number
  iat?: number
  jti?: string
  [key: string]: unknown
}

export type JwtKind = 'JWS' | 'JWE' | 'unknown'

export interface DecodedJwt {
  kind: JwtKind
  header: JoseHeader
  payload?: JwtClaimsSet
  signature?: string
  segments: string[]
  raw: string
}
