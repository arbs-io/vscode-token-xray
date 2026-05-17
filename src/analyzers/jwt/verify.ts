import {
  importJWK,
  importSPKI,
  importX509,
  jwtVerify,
  JWK,
} from 'jose'

type VerifyKey = CryptoKey | Uint8Array

export type VerifyKeySource =
  | { kind: 'jwk'; jwk: JWK; kid?: string }
  | { kind: 'pem-spki'; pem: string; alg: string; kid?: string }
  | { kind: 'pem-x509'; pem: string; alg: string; kid?: string }
  | { kind: 'symmetric'; secret: string; alg: string; kid?: string }

export interface VerifyOptions {
  keys: VerifyKeySource[]
  issuer?: string
  audience?: string
}

export interface VerifyResult {
  verified: boolean
  alg?: string
  kid?: string
  matchedKeyKid?: string
  error?: string
}

async function materialiseKey(source: VerifyKeySource): Promise<{
  key: VerifyKey
  alg: string
  kid?: string
}> {
  switch (source.kind) {
    case 'jwk': {
      const key = (await importJWK(source.jwk)) as VerifyKey
      const alg = source.jwk.alg
      if (!alg) throw new Error('JWK missing "alg"')
      return { key, alg, kid: source.kid ?? source.jwk.kid }
    }
    case 'pem-spki': {
      const key = await importSPKI(source.pem, source.alg)
      return { key, alg: source.alg, kid: source.kid }
    }
    case 'pem-x509': {
      const key = await importX509(source.pem, source.alg)
      return { key, alg: source.alg, kid: source.kid }
    }
    case 'symmetric': {
      return {
        key: new TextEncoder().encode(source.secret),
        alg: source.alg,
        kid: source.kid,
      }
    }
  }
}

export async function verifyJwt(
  token: string,
  options: VerifyOptions
): Promise<VerifyResult> {
  if (!token) return { verified: false, error: 'Empty token' }
  if (!options.keys || options.keys.length === 0) {
    return { verified: false, error: 'No keys configured' }
  }

  const header = parseHeaderUnsafe(token)
  const tokenKid = header?.kid as string | undefined
  const tokenAlg = header?.alg as string | undefined

  const candidates = tokenKid
    ? options.keys.filter((k) => kidOf(k) === undefined || kidOf(k) === tokenKid)
    : options.keys

  let lastError: string | undefined

  for (const candidate of candidates) {
    let materialised
    try {
      materialised = await materialiseKey(candidate)
    } catch (e) {
      lastError = (e as Error).message
      continue
    }
    if (tokenAlg && materialised.alg !== tokenAlg) {
      lastError = `Algorithm mismatch: token "${tokenAlg}" vs key "${materialised.alg}"`
      continue
    }
    try {
      const { protectedHeader } = await jwtVerify(token, materialised.key, {
        algorithms: [materialised.alg],
        issuer: options.issuer,
        audience: options.audience,
      })
      return {
        verified: true,
        alg: protectedHeader.alg,
        kid: protectedHeader.kid,
        matchedKeyKid: materialised.kid,
      }
    } catch (e) {
      lastError = (e as Error).message
    }
  }

  return { verified: false, error: lastError ?? 'No key matched the token' }
}

function kidOf(source: VerifyKeySource): string | undefined {
  if (source.kind === 'jwk') return source.kid ?? source.jwk.kid
  return source.kid
}

function parseHeaderUnsafe(token: string): Record<string, unknown> | undefined {
  const seg = token.split('.')[0]
  if (!seg) return undefined
  try {
    const padded = seg.replace(/-/g, '+').replace(/_/g, '/')
    const json = Buffer.from(padded, 'base64').toString('utf8')
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return undefined
  }
}
