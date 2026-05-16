import { Finding } from '../../core/types'
import { DecodedPgp } from './decoder'

const RFC_9580_URL = 'https://datatracker.ietf.org/doc/html/rfc9580#section-6'

/**
 * Map a decoded PGP block to the findings the UI surfaces.
 *
 * Emitted ids:
 *   - `pgp.privateKey.present` (error)   — armored `PRIVATE KEY BLOCK`.
 *   - `pgp.message.encrypted`  (info)    — armored `MESSAGE` block (opaque
 *                                          ciphertext to anyone without
 *                                          the recipient's secret key).
 *   - `pgp.armor.malformed`    (warning) — base64 body wouldn't decode, or
 *                                          the first packet's high bit is 0
 *                                          (RFC 4880 §4.2 requires bit 7
 *                                          to be 1 in every packet header).
 */
export function evaluatePgp(decoded: DecodedPgp): Finding[] {
  const findings: Finding[] = []

  if (decoded.blockType === 'PRIVATE KEY BLOCK') {
    findings.push({
      id: 'pgp.privateKey.present',
      severity: 'error',
      message:
        'Armored PGP private key block detected. Private keys must never be committed to source control or shared in transit — rotate the key and remove the block.',
      docUrl: RFC_9580_URL,
    })
  }

  if (decoded.blockType === 'MESSAGE') {
    findings.push({
      id: 'pgp.message.encrypted',
      severity: 'info',
      message:
        'Armored PGP MESSAGE block detected. The contents are encrypted and cannot be inspected without the recipient private key.',
      docUrl: RFC_9580_URL,
    })
  }

  if (isMalformedArmor(decoded)) {
    findings.push({
      id: 'pgp.armor.malformed',
      severity: 'warning',
      message:
        'PGP armored block could not be decoded — the base64 body was malformed or the first packet header is not valid OpenPGP (RFC 4880 §4.2 requires bit 7 of the tag byte to be set).',
      docUrl: 'https://datatracker.ietf.org/doc/html/rfc4880#section-4.2',
    })
  }

  return findings
}

/**
 * Decide whether the decoded block looks malformed. We never flag
 * `SIGNED MESSAGE` because its body before the inner SIGNATURE armor
 * is cleartext, so a missing `firstPacketTag` there is expected.
 */
function isMalformedArmor(decoded: DecodedPgp): boolean {
  if (decoded.blockType === 'SIGNED MESSAGE') return false
  if (decoded.firstPacketTag === undefined) return true
  // RFC 4880 §4.2: every packet header byte has bit 7 set.
  return (decoded.firstPacketTag & 0x80) === 0
}
