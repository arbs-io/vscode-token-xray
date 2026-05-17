import { Finding } from '../../core/types'
import { DecodedX509 } from './decoder'
import { isWeakSignatureAlgorithm } from './sigalg'

export interface X509FindingOptions {
  now?: number
}

const SHORT_REMAINING_MS = 30 * 24 * 60 * 60 * 1000

export function evaluateX509(decoded: DecodedX509, options: X509FindingOptions = {}): Finding[] {
  const findings: Finding[] = []
  const now = options.now ?? Date.now()

  const notBefore = Date.parse(decoded.validFrom)
  const notAfter = Date.parse(decoded.validTo)
  if (Number.isFinite(notBefore) && notBefore > now) {
    findings.push({
      id: 'x509.validity.notYetValid',
      severity: 'warning',
      message: `Certificate is not valid until ${new Date(notBefore).toISOString()}.`,
    })
  }
  if (Number.isFinite(notAfter)) {
    if (notAfter <= now) {
      findings.push({
        id: 'x509.validity.expired',
        severity: 'error',
        message: `Certificate expired at ${new Date(notAfter).toISOString()}.`,
      })
    } else if (notAfter - now < SHORT_REMAINING_MS) {
      findings.push({
        id: 'x509.validity.expiringSoon',
        severity: 'warning',
        message: `Certificate expires in less than 30 days (${new Date(notAfter).toISOString()}).`,
      })
    }
  }

  if (decoded.keyAlgorithm === 'rsa') {
    const match = /RSA-(\d+)/.exec(decoded.keyDetails)
    const bits = match ? Number(match[1]) : 0
    if (bits > 0 && bits < 2048) {
      findings.push({
        id: 'x509.key.weakRsa',
        severity: 'error',
        message: `RSA key is ${bits} bits — below the 2048-bit minimum.`,
      })
    }
  }

  if (isWeakSignatureAlgorithm(decoded.signatureAlgorithm)) {
    findings.push({
      id: 'x509.signature.weakAlgorithm',
      severity: 'error',
      message: `Signature uses ${decoded.signatureAlgorithm} — weak hash. Reissue with SHA-256 or stronger.`,
    })
  }

  if (decoded.selfSigned) {
    findings.push({
      id: 'x509.signature.selfSigned',
      severity: 'info',
      message: 'Certificate is self-signed (Subject == Issuer). Acceptable for development; not for public-trust use.',
    })
  }

  if (decoded.subjectAltNames.length === 0) {
    findings.push({
      id: 'x509.san.missing',
      severity: 'warning',
      message: 'No Subject Alternative Names. Modern browsers reject certificates that rely on the Common Name alone.',
    })
  }

  return findings
}
