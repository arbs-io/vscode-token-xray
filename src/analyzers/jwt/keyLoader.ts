import { JWK } from 'jose'
import { VerifyKeySource } from './verify'

interface RawKeyConfig {
  pem?: string
  alg?: string
  kid?: string
  secret?: string
  kty?: string
  [key: string]: unknown
}

/** Why a `tokenXray.jwt.keys` entry was dropped. Logged by the provider. */
export interface KeyConfigIssue {
  /** Zero-based index in the user's `tokenXray.jwt.keys` array. */
  index: number
  /** Short, human-readable reason. */
  reason: string
}

function classify(item: unknown): { source?: VerifyKeySource; reason?: string } {
  if (item === null || item === undefined) {
    return { reason: 'entry is null/undefined' }
  }
  if (typeof item !== 'object' || Array.isArray(item)) {
    return { reason: `entry must be an object (got ${Array.isArray(item) ? 'array' : typeof item})` }
  }
  const cfg = item as RawKeyConfig
  const kid = typeof cfg.kid === 'string' ? cfg.kid : undefined

  if (typeof cfg.pem === 'string') {
    if (typeof cfg.alg !== 'string') {
      return { reason: 'pem entry is missing string "alg" (e.g. "RS256")' }
    }
    const isCert = cfg.pem.includes('BEGIN CERTIFICATE')
    return { source: { kind: isCert ? 'pem-x509' : 'pem-spki', pem: cfg.pem, alg: cfg.alg, kid } }
  }
  if (typeof cfg.secret === 'string') {
    if (typeof cfg.alg !== 'string') {
      return { reason: 'secret entry is missing string "alg" (e.g. "HS256")' }
    }
    return { source: { kind: 'symmetric', secret: cfg.secret, alg: cfg.alg, kid } }
  }
  if (typeof cfg.kty === 'string') {
    return { source: { kind: 'jwk', jwk: cfg as unknown as JWK, kid } }
  }
  return {
    reason:
      'entry must contain "pem"+"alg", "secret"+"alg", or a JWK with "kty"',
  }
}

/**
 * Parses `tokenXray.jwt.keys` user config into the strongly-typed
 * `VerifyKeySource` shapes the verifier consumes. Returns an empty
 * array when `raw` is not an array. Use {@link keySourcesFromConfigDetailed}
 * to also receive a per-entry diagnostic list explaining why entries
 * were skipped — surfaced through the debug output channel.
 */
export function keySourcesFromConfig(raw: unknown): VerifyKeySource[] {
  return keySourcesFromConfigDetailed(raw).sources
}

export interface KeySourcesResult {
  sources: VerifyKeySource[]
  issues: KeyConfigIssue[]
}

export function keySourcesFromConfigDetailed(raw: unknown): KeySourcesResult {
  if (!Array.isArray(raw)) return { sources: [], issues: [] }
  const sources: VerifyKeySource[] = []
  const issues: KeyConfigIssue[] = []
  raw.forEach((item, index) => {
    const { source, reason } = classify(item)
    if (source) sources.push(source)
    else if (reason) issues.push({ index, reason })
  })
  return { sources, issues }
}
