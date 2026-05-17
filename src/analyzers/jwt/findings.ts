import { Finding } from '../../core/types'
import { recognizeIssuer } from './issuerRecognition'
import { DecodedJwt } from './types'

export interface JwtFindingOptions {
  now?: number
}

const DANGEROUS_ALGS = new Set(['none', 'None', 'NONE'])
const WEAK_ALGS = new Set(['HS256'])

export function evaluateJwt(decoded: DecodedJwt, options: JwtFindingOptions = {}): Finding[] {
  const findings: Finding[] = []
  const nowSec = Math.floor((options.now ?? Date.now()) / 1000)

  const alg = decoded.header.alg
  findings.push(...evaluateAlg(alg))

  if (decoded.kind === 'JWS' && !decoded.header.kid && alg && alg !== 'none') {
    findings.push({
      id: 'jwt.header.kid.missing',
      severity: 'info',
      message: 'No "kid" in header — verifiers cannot select the correct key during rotation.',
    })
  }

  if (decoded.header.crit && decoded.header.crit.length > 0) {
    findings.push({
      id: 'jwt.header.crit',
      severity: 'warning',
      message: `"crit" header lists extensions (${decoded.header.crit.join(', ')}). Verifiers must understand each one or reject the token.`,
    })
  }

  const payload = decoded.payload
  if (!payload) return findings

  findings.push(
    ...evaluateExp(payload, nowSec),
    ...evaluateNbf(payload, nowSec),
    ...evaluateIat(payload, nowSec),
    ...evaluateAud(payload),
    ...evaluateIss(payload),
  )

  return findings
}

function evaluateAlg(alg: unknown): Finding[] {
  if (alg === undefined) {
    return [{
      id: 'jwt.header.alg.missing',
      severity: 'error',
      message: 'JOSE header is missing the "alg" field.',
      docUrl: 'https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1',
    }]
  }
  if (typeof alg === 'string' && DANGEROUS_ALGS.has(alg)) {
    return [{
      id: 'jwt.alg.none',
      severity: 'error',
      message: 'Token uses "alg":"none" — signature is not verified. Reject in production.',
      docUrl: 'https://www.rfc-editor.org/rfc/rfc7518#section-3.6',
    }]
  }
  if (typeof alg === 'string' && WEAK_ALGS.has(alg)) {
    return [{
      id: 'jwt.alg.weak',
      severity: 'warning',
      message: `Token uses ${alg}; consider an asymmetric algorithm (RS256/ES256/EdDSA) for tokens shared across services.`,
    }]
  }
  return []
}

function evaluateExp(payload: Record<string, unknown>, nowSec: number): Finding[] {
  if (payload.exp === undefined) {
    return [{
      id: 'jwt.exp.missing',
      severity: 'warning',
      message: '"exp" claim is missing — token has no expiry.',
    }]
  }
  if (typeof payload.exp !== 'number') {
    return [{
      id: 'jwt.exp.invalid',
      severity: 'error',
      message: '"exp" must be a NumericDate (seconds since epoch).',
    }]
  }
  if (payload.exp <= nowSec) {
    return [{
      id: 'jwt.exp.expired',
      severity: 'error',
      message: `Token expired at ${new Date(payload.exp * 1000).toISOString()}.`,
    }]
  }
  return []
}

function evaluateNbf(payload: Record<string, unknown>, nowSec: number): Finding[] {
  if (payload.nbf === undefined) return []
  if (typeof payload.nbf !== 'number') {
    return [{
      id: 'jwt.nbf.invalid',
      severity: 'error',
      message: '"nbf" must be a NumericDate (seconds since epoch).',
    }]
  }
  if (payload.nbf > nowSec) {
    return [{
      id: 'jwt.nbf.future',
      severity: 'warning',
      message: `Token not valid until ${new Date(payload.nbf * 1000).toISOString()}.`,
    }]
  }
  return []
}

function evaluateIat(payload: Record<string, unknown>, nowSec: number): Finding[] {
  if (typeof payload.iat === 'number' && payload.iat > nowSec + 60) {
    return [{
      id: 'jwt.iat.future',
      severity: 'warning',
      message: `"iat" is in the future (${new Date(payload.iat * 1000).toISOString()}). Clock skew or forged token.`,
    }]
  }
  return []
}

function evaluateAud(payload: Record<string, unknown>): Finding[] {
  if (payload.aud === undefined) {
    return [{
      id: 'jwt.aud.missing',
      severity: 'info',
      message: '"aud" claim is missing — verifiers cannot assert intended audience.',
    }]
  }
  return []
}

function evaluateIss(payload: Record<string, unknown>): Finding[] {
  if (payload.iss === undefined) {
    return [{
      id: 'jwt.iss.missing',
      severity: 'info',
      message: '"iss" claim is missing — verifiers cannot assert the issuer.',
    }]
  }
  if (typeof payload.iss !== 'string') return []
  const recognized = recognizeIssuer(payload.iss)
  if (!recognized) return []

  const parts: string[] = [`Issued by ${recognized.pattern.name}.`]
  if (recognized.tenant) parts.push(`Tenant/pool: ${recognized.tenant}.`)
  for (const [key, value] of Object.entries(recognized.extras)) {
    parts.push(`${key}: ${value}.`)
  }
  if (recognized.pattern.guidance) parts.push(recognized.pattern.guidance)
  return [{
    id: `jwt.idp.${recognized.pattern.id}`,
    severity: 'info',
    message: parts.join(' '),
    docUrl: recognized.pattern.docUrl,
  }]
}
