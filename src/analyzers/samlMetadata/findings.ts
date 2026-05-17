import { Finding } from '../../core/types'
import { DecodedSamlMetadata, SamlMetadataEntity, SamlMetadataSigningCert } from './decoder'

export interface SamlMetadataFindingOptions {
  now?: number
}

const SHORT_REMAINING_MS = 30 * 24 * 60 * 60 * 1000

/**
 * Evaluate a decoded SAML metadata document and surface security findings.
 *
 * Per-entity findings:
 *   - `samlMeta.signing.missing` (warning) — metadata is not signed.
 *   - `samlMeta.role.missing`    (warning) — entity has neither IDPSSO nor SPSSO descriptor.
 *   - `samlMeta.cert.expired`    (error)   — at least one signing cert's notAfter is in the past.
 *   - `samlMeta.cert.expiringSoon` (warning) — at least one signing cert's notAfter is < 30 days away.
 */
export function evaluateSamlMetadata(
  decoded: DecodedSamlMetadata,
  options: SamlMetadataFindingOptions = {}
): Finding[] {
  const now = options.now ?? Date.now()
  const out: Finding[] = []
  for (const entity of decoded.entities) {
    out.push(...evaluateEntity(entity, now, decoded.entities.length > 1))
  }
  return out
}

function evaluateEntity(entity: SamlMetadataEntity, now: number, multi: boolean): Finding[] {
  const out: Finding[] = []
  const prefix = multi ? ` (entity: ${entity.entityId})` : ''

  if (!entity.signed) {
    out.push({
      id: 'samlMeta.signing.missing',
      severity: 'warning',
      message: `SAML metadata is not signed${prefix}. Consumers cannot verify authenticity without an out-of-band trust anchor.`,
    })
  }

  if (entity.roles.length === 0) {
    out.push({
      id: 'samlMeta.role.missing',
      severity: 'warning',
      message: `EntityDescriptor has neither IDPSSODescriptor nor SPSSODescriptor${prefix}.`,
    })
  }

  const certs: SamlMetadataSigningCert[] = entity.roles.flatMap((r) => r.signingCerts)
  for (const cert of certs) {
    const expiresAt = cert.notAfter.getTime()
    if (!Number.isFinite(expiresAt)) continue
    if (expiresAt <= now) {
      out.push({
        id: 'samlMeta.cert.expired',
        severity: 'error',
        message: `Signing certificate expired at ${cert.notAfter.toISOString()}${prefix}. Subject: ${cert.subject}.`,
      })
    } else if (expiresAt - now < SHORT_REMAINING_MS) {
      out.push({
        id: 'samlMeta.cert.expiringSoon',
        severity: 'warning',
        message: `Signing certificate expires within 30 days (${cert.notAfter.toISOString()})${prefix}. Subject: ${cert.subject}.`,
      })
    }
  }

  return out
}
