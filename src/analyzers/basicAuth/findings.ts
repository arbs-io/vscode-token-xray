import { Finding } from '../../core/types'
import { DecodedBasic } from './decoder'

/**
 * Mask a password value to its trailing characters.
 *
 * Default keeps the last 2 characters and prefixes with 8 asterisks:
 *   `abcdefgh` → `********gh`
 *   `ab`       → `********ab`
 *   `a`        → `********a`  (cannot reveal more than the password length)
 *   ``         → `********`
 */
export function maskPassword(password: string, keep = 2): string {
  const stars = '*'.repeat(8)
  if (keep <= 0) return stars
  if (password.length <= keep) return `${stars}${password}`
  return `${stars}${password.slice(-keep)}`
}

/**
 * Emit a `basic.cred.plaintext` finding (error severity) for a successfully
 * decoded HTTP Basic credential. The message includes the username and a
 * masked password (last 2 characters preserved).
 */
export function findingsForDecodedBasic(decoded: DecodedBasic): Finding[] {
  return [
    {
      id: 'basic.cred.plaintext',
      severity: 'error',
      message: `HTTP Basic credentials in plaintext — username "${decoded.user}", password ${maskPassword(decoded.password)}. Rotate immediately and move to a secret store.`,
      docUrl: 'https://datatracker.ietf.org/doc/html/rfc7617',
    },
  ]
}

/**
 * Emit a `basic.cred.malformed` finding (warning severity) when input
 * matched the Authorization-Basic shape but the credential could not be
 * decoded (invalid base64 / no colon / empty user or password).
 */
export function findingsForMalformedBasic(): Finding[] {
  return [
    {
      id: 'basic.cred.malformed',
      severity: 'warning',
      message: 'Authorization: Basic header is present but the credential could not be base64-decoded into a non-empty "user:password" pair.',
      docUrl: 'https://datatracker.ietf.org/doc/html/rfc7617',
    },
  ]
}
