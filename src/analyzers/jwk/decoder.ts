import { base64UrlDecodeBytes } from '../../core/base64url'

export type JwkKind = 'jwk' | 'jwks'

export interface DecodedJwk {
  kty: string
  kid?: string
  use?: string
  alg?: string
  keyOps?: string[]
  curve?: string
  keySizeBits?: number
  hasPrivateMaterial: boolean
  raw: Record<string, unknown>
}

export interface DecodedJwks {
  kind: 'jwks'
  keys: DecodedJwk[]
  raw: Record<string, unknown>
}

export interface DecodedSingleJwk {
  kind: 'jwk'
  key: DecodedJwk
  raw: Record<string, unknown>
}

export type DecodedJwkInput = DecodedJwks | DecodedSingleJwk

const VALID_KTY = new Set(['RSA', 'EC', 'OKP', 'oct'])

export function looksLikeJwkJson(text: string): boolean {
  const t = text.trim()
  if (!t.startsWith('{')) return false
  return /"kty"\s*:|"keys"\s*:\s*\[/.test(t)
}

export function decodeJwkInput(text: string): DecodedJwkInput {
  const t = text.trim()
  if (!t.startsWith('{')) throw new Error('Input does not look like JSON')
  let parsed: unknown
  try {
    parsed = JSON.parse(t)
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`)
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('JWK / JWKS must be a JSON object')
  }
  const obj = parsed as Record<string, unknown>
  if (Array.isArray(obj.keys)) {
    const keys = (obj.keys as unknown[])
      .filter((k): k is Record<string, unknown> => !!k && typeof k === 'object')
      .map(decodeSingleJwk)
    return { kind: 'jwks', keys, raw: obj }
  }
  if (typeof obj.kty === 'string') {
    return { kind: 'jwk', key: decodeSingleJwk(obj), raw: obj }
  }
  throw new Error('Object is neither a JWK (missing "kty") nor a JWKS (missing "keys" array)')
}

function decodeSingleJwk(raw: Record<string, unknown>): DecodedJwk {
  const kty = typeof raw.kty === 'string' ? raw.kty : 'unknown'
  if (!VALID_KTY.has(kty)) {
    return {
      kty,
      kid: stringOrUndef(raw.kid),
      use: stringOrUndef(raw.use),
      alg: stringOrUndef(raw.alg),
      keyOps: stringArrayOrUndef(raw.key_ops),
      hasPrivateMaterial: false,
      raw,
    }
  }

  return {
    kty,
    kid: stringOrUndef(raw.kid),
    use: stringOrUndef(raw.use),
    alg: stringOrUndef(raw.alg),
    keyOps: stringArrayOrUndef(raw.key_ops),
    curve: kty === 'EC' || kty === 'OKP' ? stringOrUndef(raw.crv) : undefined,
    keySizeBits: deriveKeySizeBits(raw, kty),
    hasPrivateMaterial: containsPrivateMaterial(raw, kty),
    raw,
  }
}

function deriveKeySizeBits(raw: Record<string, unknown>, kty: string): number | undefined {
  if (kty === 'RSA' && typeof raw.n === 'string') {
    try {
      return base64UrlDecodeBytes(raw.n).length * 8
    } catch {
      return undefined
    }
  }
  if (kty === 'oct' && typeof raw.k === 'string') {
    try {
      return base64UrlDecodeBytes(raw.k).length * 8
    } catch {
      return undefined
    }
  }
  if (kty === 'EC' && typeof raw.x === 'string') {
    try {
      return base64UrlDecodeBytes(raw.x).length * 8
    } catch {
      return undefined
    }
  }
  return undefined
}

function containsPrivateMaterial(raw: Record<string, unknown>, kty: string): boolean {
  switch (kty) {
    case 'RSA':
      return ['d', 'p', 'q', 'dp', 'dq', 'qi'].some((k) => typeof raw[k] === 'string')
    case 'EC':
    case 'OKP':
      return typeof raw.d === 'string'
    case 'oct':
      return typeof raw.k === 'string'
    default:
      return false
  }
}

function stringOrUndef(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined
}

function stringArrayOrUndef(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined
  const arr = v.filter((x): x is string => typeof x === 'string')
  return arr.length ? arr : undefined
}
