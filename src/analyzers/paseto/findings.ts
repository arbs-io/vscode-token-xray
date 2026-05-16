import { Finding } from '../../core/types'
import { DecodedPaseto } from './decoder'

/**
 * Map a decoded PASETO token to the set of findings the UI surfaces.
 *
 * Emitted ids:
 *   - `paseto.version.deprecated` (info) — v1 / v2 use NIST primitives that
 *     have been superseded by v3 / v4. Recommend migration.
 *   - `paseto.purpose.local`      (info) — encrypted payload, contents
 *     cannot be inspected without the symmetric key.
 *   - `paseto.payload.invalid`    (warning) — a `public` token's payload
 *     either failed base64url decode or the claims segment was not JSON.
 */
export function evaluatePaseto(decoded: DecodedPaseto): Finding[] {
  const findings: Finding[] = []

  if (decoded.version === 'v1' || decoded.version === 'v2') {
    findings.push({
      id: 'paseto.version.deprecated',
      severity: 'info',
      message: `PASETO ${decoded.version} uses NIST primitives that have been superseded. Prefer v3 (NIST) or v4 (modern) for new tokens.`,
      docUrl: 'https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Readme.md',
    })
  }

  if (decoded.purpose === 'local') {
    findings.push({
      id: 'paseto.purpose.local',
      severity: 'info',
      message: 'PASETO local token — payload is encrypted and cannot be inspected without the symmetric key.',
      docUrl: 'https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Readme.md',
    })
  }

  if (decoded.payloadInvalid) {
    findings.push({
      id: 'paseto.payload.invalid',
      severity: 'warning',
      message: `PASETO ${decoded.version}.${decoded.purpose} payload could not be base64url-decoded or did not contain a JSON claims object.`,
    })
  }

  return findings
}
