import { Finding } from '../../core/types'
import { DecodedSaml } from './decoder'

export interface SamlFindingOptions {
  now?: number
}

export function evaluateSaml(decoded: DecodedSaml, options: SamlFindingOptions = {}): Finding[] {
  const findings: Finding[] = []
  const now = options.now ?? Date.now()

  if (decoded.kind === 'unknown') {
    findings.push({
      id: 'saml.kind.unknown',
      severity: 'warning',
      message: 'Could not identify the SAML element kind (Response / Assertion / EncryptedAssertion).',
    })
    return findings
  }

  if (decoded.isEncrypted) {
    findings.push({
      id: 'saml.assertion.encrypted',
      severity: 'info',
      message: 'Assertion is encrypted (<EncryptedAssertion>). Decryption requires the SP private key.',
    })
  }

  if (!decoded.signature.present) {
    findings.push({
      id: 'saml.signature.missing',
      severity: 'error',
      message: 'No <ds:Signature> element. Unsigned SAML responses must be rejected by SPs.',
    })
  } else if (decoded.signature.algorithm) {
    const alg = decoded.signature.algorithm.toLowerCase()
    if (alg.includes('rsa-sha1') || alg.includes('dsa-sha1')) {
      findings.push({
        id: 'saml.signature.weakAlgorithm',
        severity: 'warning',
        message: `Signature uses a SHA-1 based algorithm (${decoded.signature.algorithm}). Prefer SHA-256 or stronger.`,
      })
    }
  }

  if (decoded.signature.digestAlgorithm) {
    const dig = decoded.signature.digestAlgorithm.toLowerCase()
    if (dig.includes('sha1')) {
      findings.push({
        id: 'saml.signature.weakDigest',
        severity: 'warning',
        message: `Reference digest uses SHA-1 (${decoded.signature.digestAlgorithm}). Prefer SHA-256.`,
      })
    }
  }

  if (decoded.conditions) {
    if (decoded.conditions.notBefore) {
      const nb = Date.parse(decoded.conditions.notBefore)
      if (Number.isFinite(nb) && nb > now) {
        findings.push({
          id: 'saml.conditions.notYetValid',
          severity: 'warning',
          message: `Assertion not valid until ${new Date(nb).toISOString()}.`,
        })
      }
    }
    if (decoded.conditions.notOnOrAfter) {
      const na = Date.parse(decoded.conditions.notOnOrAfter)
      if (Number.isFinite(na) && na <= now) {
        findings.push({
          id: 'saml.conditions.expired',
          severity: 'error',
          message: `Assertion expired at ${new Date(na).toISOString()}.`,
        })
      }
    }
    if (decoded.conditions.audiences.length === 0) {
      findings.push({
        id: 'saml.conditions.noAudience',
        severity: 'warning',
        message: 'No <AudienceRestriction> — SP cannot verify the assertion is intended for it.',
      })
    }
  } else if (!decoded.isEncrypted) {
    findings.push({
      id: 'saml.conditions.missing',
      severity: 'warning',
      message: 'No <Conditions> element — assertion has no validity window.',
    })
  }

  if (!decoded.issuer) {
    findings.push({
      id: 'saml.issuer.missing',
      severity: 'warning',
      message: '<Issuer> is missing — SP cannot validate identity provider trust.',
    })
  }

  return findings
}
