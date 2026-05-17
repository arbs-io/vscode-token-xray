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

export function keySourcesFromConfig(raw: unknown): VerifyKeySource[] {
  if (!Array.isArray(raw)) return []
  const out: VerifyKeySource[] = []
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue
    const cfg = item as RawKeyConfig
    const kid = typeof cfg.kid === 'string' ? cfg.kid : undefined

    if (typeof cfg.pem === 'string' && typeof cfg.alg === 'string') {
      const isCert = cfg.pem.includes('BEGIN CERTIFICATE')
      out.push({ kind: isCert ? 'pem-x509' : 'pem-spki', pem: cfg.pem, alg: cfg.alg, kid })
      continue
    }
    if (typeof cfg.secret === 'string' && typeof cfg.alg === 'string') {
      out.push({ kind: 'symmetric', secret: cfg.secret, alg: cfg.alg, kid })
      continue
    }
    if (typeof cfg.kty === 'string') {
      out.push({ kind: 'jwk', jwk: cfg as unknown as JWK, kid })
    }
  }
  return out
}
