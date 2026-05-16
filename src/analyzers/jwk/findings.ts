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

function evaluateSingle(key: DecodedJwk, prefix: string): Finding[] {
  const out: Finding[] = []
  const tag = (id: string) => `jwk.${prefix}${id}`

  if (!['RSA', 'EC', 'OKP', 'oct'].includes(key.kty)) {
    out.push({
      id: tag('kty.unknown'),
      severity: 'warning',
      message: `Unknown key type "${key.kty}". Expected RSA, EC, OKP, or oct.`,
    })
    return out
  }

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

  if (key.kty === 'RSA') {
    if (key.keySizeBits === undefined) {
      out.push({ id: tag('rsa.modulus.missing'), severity: 'error', message: 'RSA key missing modulus "n".' })
    } else if (key.keySizeBits < 2048) {
      out.push({
        id: tag('rsa.key.weak'),
        severity: 'error',
        message: `RSA key is ${key.keySizeBits} bits — below the 2048-bit minimum.`,
      })
    }
  }

  if (key.kty === 'oct' && key.keySizeBits !== undefined && key.keySizeBits < 128) {
    out.push({
      id: tag('oct.key.weak'),
      severity: 'error',
      message: `Symmetric key is ${key.keySizeBits} bits — below the 128-bit minimum.`,
    })
  }

  if ((key.kty === 'EC' || key.kty === 'OKP') && key.curve) {
    if (!KNOWN_CURVES.has(key.curve)) {
      out.push({
        id: tag('curve.unknown'),
        severity: 'warning',
        message: `Unknown curve "${key.curve}".`,
      })
    } else if (WEAK_CURVES.has(key.curve)) {
      out.push({
        id: tag('curve.weak'),
        severity: 'warning',
        message: `Curve "${key.curve}" is deprecated or weak. Prefer P-256 / P-384 / Ed25519.`,
      })
    }
  }

  if (key.use && !['sig', 'enc'].includes(key.use)) {
    out.push({
      id: tag('use.invalid'),
      severity: 'warning',
      message: `"use" must be "sig" or "enc"; got "${key.use}".`,
    })
  }

  return out
}
