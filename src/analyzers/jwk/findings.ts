import { Finding } from '../../core/types'
import { DecodedJwk, DecodedJwkInput } from './decoder'

const WEAK_CURVES = new Set(['P-192', 'P-224', 'secp256k1'])
const KNOWN_CURVES = new Set([
  'P-256',
  'P-384',
  'P-521',
  'secp256k1',
  'P-192',
  'P-224',
  'Ed25519',
  'Ed448',
  'X25519',
  'X448',
])

export function evaluateJwk(input: DecodedJwkInput): Finding[] {
  if (input.kind === 'jwk') {
    return evaluateSingle(input.key, '')
  }
  if (input.keys.length === 0) {
    return [
      {
        id: 'jwks.empty',
        severity: 'warning',
        message: 'JWKS contains no keys.',
      },
    ]
  }
  const out: Finding[] = []
  for (let i = 0; i < input.keys.length; i++) {
    out.push(...evaluateSingle(input.keys[i], `keys[${i}].`))
  }
  return out
}

function evaluateRsaKey(key: DecodedJwk, tag: (id: string) => string): Finding[] {
  if (key.kty !== 'RSA') return []
  if (key.keySizeBits === undefined) {
    return [{ id: tag('rsa.modulus.missing'), severity: 'error', message: 'RSA key missing modulus "n".' }]
  }
  if (key.keySizeBits < 2048) {
    return [{
      id: tag('rsa.key.weak'),
      severity: 'error',
      message: `RSA key is ${key.keySizeBits} bits — below the 2048-bit minimum.`,
    }]
  }
  return []
}

function evaluateCurve(key: DecodedJwk, tag: (id: string) => string): Finding[] {
  if ((key.kty !== 'EC' && key.kty !== 'OKP') || !key.curve) return []
  if (!KNOWN_CURVES.has(key.curve)) {
    return [{ id: tag('curve.unknown'), severity: 'warning', message: `Unknown curve "${key.curve}".` }]
  }
  if (WEAK_CURVES.has(key.curve)) {
    return [{
      id: tag('curve.weak'),
      severity: 'warning',
      message: `Curve "${key.curve}" is deprecated or weak. Prefer P-256 / P-384 / Ed25519.`,
    }]
  }
  return []
}

function evaluateSingle(key: DecodedJwk, prefix: string): Finding[] {
  const tag = (id: string) => `jwk.${prefix}${id}`

  if (!['RSA', 'EC', 'OKP', 'oct'].includes(key.kty)) {
    return [{
      id: tag('kty.unknown'),
      severity: 'warning',
      message: `Unknown key type "${key.kty}". Expected RSA, EC, OKP, or oct.`,
    }]
  }

  const out: Finding[] = []

  if (!key.kid) {
    out.push({
      id: tag('kid.missing'),
      severity: 'info',
      message: 'No "kid" — verifiers cannot select this key during rotation.',
    })
  }

  if (key.hasPrivateMaterial) {
    out.push({
      id: tag('private.present'),
      severity: 'error',
      message: 'Key contains PRIVATE material. JWKS endpoints must publish only public keys.',
    })
  }

  out.push(...evaluateRsaKey(key, tag))

  if (key.kty === 'oct' && key.keySizeBits !== undefined && key.keySizeBits < 128) {
    out.push({
      id: tag('oct.key.weak'),
      severity: 'error',
      message: `Symmetric key is ${key.keySizeBits} bits — below the 128-bit minimum.`,
    })
  }

  out.push(...evaluateCurve(key, tag))

  if (key.use && !['sig', 'enc'].includes(key.use)) {
    out.push({
      id: tag('use.invalid'),
      severity: 'warning',
      message: `"use" must be "sig" or "enc"; got "${key.use}".`,
    })
  }

  return out
}
