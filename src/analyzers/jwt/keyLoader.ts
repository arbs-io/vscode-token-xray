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

function keySourceFromItem(item: unknown): VerifyKeySource | undefined {
  if (!item || typeof item !== 'object') return undefined
  const cfg = item as RawKeyConfig
  const kid = typeof cfg.kid === 'string' ? cfg.kid : undefined

  if (typeof cfg.pem === 'string' && typeof cfg.alg === 'string') {
    const isCert = cfg.pem.includes('BEGIN CERTIFICATE')
    return { kind: isCert ? 'pem-x509' : 'pem-spki', pem: cfg.pem, alg: cfg.alg, kid }
  }
  if (typeof cfg.secret === 'string' && typeof cfg.alg === 'string') {
    return { kind: 'symmetric', secret: cfg.secret, alg: cfg.alg, kid }
  }
  if (typeof cfg.kty === 'string') {
    return { kind: 'jwk', jwk: cfg as unknown as JWK, kid }
  }
  return undefined
}

export function keySourcesFromConfig(raw: unknown): VerifyKeySource[] {
  if (!Array.isArray(raw)) return []
  const out: VerifyKeySource[] = []
  for (const item of raw) {
    const source = keySourceFromItem(item)
    if (source) out.push(source)
  }
  return out
}
