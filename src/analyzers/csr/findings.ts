import { Finding } from '../../core/types'
import { DecodedCsr } from './decoder'

const CSR_DOC_URL =
  'https://datatracker.ietf.org/doc/html/rfc2986'

/**
 * Map a decoded CSR to the set of findings the UI surfaces.
 *
 * Emitted ids:
 *   - `csr.key.weakRsa`  (error)   — RSA modulus < 2048 bits.
 *   - `csr.san.missing`  (warning) — no SubjectAltName extension requested.
 */
export function evaluateCsr(decoded: DecodedCsr): Finding[] {
  const findings: Finding[] = []

  if (decoded.keyAlgorithm === 'rsa' && typeof decoded.keyBits === 'number' && decoded.keyBits < 2048) {
    findings.push({
      id: 'csr.key.weakRsa',
      severity: 'error',
      message: `CSR requests RSA-${decoded.keyBits} — below the 2048-bit minimum. CAs will reject this CSR; regenerate with a stronger key.`,
      docUrl: CSR_DOC_URL,
    })
  }

  if (decoded.subjectAltNames.length === 0) {
    findings.push({
      id: 'csr.san.missing',
      severity: 'warning',
      message: 'CSR does not request a SubjectAltName extension. Modern browsers and most CAs require at least one SAN — issuance may fail or yield an unusable certificate.',
      docUrl: 'https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6',
    })
  }

  return findings
}

/**
 * Emit a `csr.parse.failed` finding (warning) when the ASN.1 walk could not
 * recognise the input as a PKCS#10 CSR. The analyzer attaches this when
 * `decodeCsr()` returns `undefined` for an otherwise PEM-armored block.
 */
export function findingsForParseFailure(): Finding[] {
  return [
    {
      id: 'csr.parse.failed',
      severity: 'warning',
      message: 'CSR PEM block could not be parsed as a PKCS#10 CertificationRequest. The ASN.1 structure was malformed or truncated.',
      docUrl: CSR_DOC_URL,
    },
  ]
}
