import { Finding } from '../../core/types'
import { DecodedSaml } from './decoder'

export interface SamlFindingOptions {
  now?: number
}

function evaluateSignature(decoded: DecodedSaml): Finding[] {
  if (!decoded.signature.present) {
    return [{
      id: 'saml.signature.missing',
      severity: 'error',
      message: 'No <ds:Signature> element. Unsigned SAML responses must be rejected by SPs.',
    }]
  }
  const out: Finding[] = []
  const alg = decoded.signature.algorithm?.toLowerCase()
  if (alg && (alg.includes('rsa-sha1') || alg.includes('dsa-sha1'))) {
    out.push({
      id: 'saml.signature.weakAlgorithm',
      severity: 'warning',
      message: `Signature uses a SHA-1 based algorithm (${decoded.signature.algorithm}). Prefer SHA-256 or stronger.`,
    })
  }
  const dig = decoded.signature.digestAlgorithm?.toLowerCase()
  if (dig?.includes('sha1')) {
    out.push({
      id: 'saml.signature.weakDigest',
      severity: 'warning',
      message: `Reference digest uses SHA-1 (${decoded.signature.digestAlgorithm}). Prefer SHA-256.`,
    })
  }
  return out
}

function evaluateConditions(decoded: DecodedSaml, now: number): Finding[] {
  if (!decoded.conditions) {
    return decoded.isEncrypted
      ? []
      : [{
          id: 'saml.conditions.missing',
          severity: 'warning',
          message: 'No <Conditions> element — assertion has no validity window.',
        }]
  }
  const out: Finding[] = []
  const { notBefore, notOnOrAfter, audiences } = decoded.conditions
  if (notBefore) {
    const nb = Date.parse(notBefore)
    if (Number.isFinite(nb) && nb > now) {
      out.push({
        id: 'saml.conditions.notYetValid',
        severity: 'warning',
        message: `Assertion not valid until ${new Date(nb).toISOString()}.`,
      })
    }
  }
  if (notOnOrAfter) {
    const na = Date.parse(notOnOrAfter)
    if (Number.isFinite(na) && na <= now) {
      out.push({
        id: 'saml.conditions.expired',
        severity: 'error',
        message: `Assertion expired at ${new Date(na).toISOString()}.`,
      })
    }
  }
  if (audiences.length === 0) {
    out.push({
      id: 'saml.conditions.noAudience',
      severity: 'warning',
      message: 'No <AudienceRestriction> — SP cannot verify the assertion is intended for it.',
    })
  }
  return out
}

export function evaluateSaml(decoded: DecodedSaml, options: SamlFindingOptions = {}): Finding[] {
  if (decoded.kind === 'unknown') {
    return [{
      id: 'saml.kind.unknown',
      severity: 'warning',
      message: 'Could not identify the SAML element kind (Response / Assertion / EncryptedAssertion).',
    }]
  }

  const findings: Finding[] = []
  const now = options.now ?? Date.now()

  if (decoded.isEncrypted) {
    findings.push({
      id: 'saml.assertion.encrypted',
      severity: 'info',
      message: 'Assertion is encrypted (<EncryptedAssertion>). Decryption requires the SP private key.',
    })
  }

  findings.push(...evaluateSignature(decoded))
  findings.push(...evaluateConditions(decoded, now))

  if (!decoded.issuer) {
    findings.push({
      id: 'saml.issuer.missing',
      severity: 'warning',
      message: '<Issuer> is missing — SP cannot validate identity provider trust.',
    })
  }

  return findings
}
