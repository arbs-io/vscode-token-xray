import { Finding } from '../../core/types'
import { DecodedSshKey } from './decoder'

const RFC_4253_URL = 'https://datatracker.ietf.org/doc/html/rfc4253#section-6.6'

/**
 * Evaluate a decoded SSH public key and surface findings.
 *
 * Emitted ids:
 *   - `sshKey.weakDsa`     (error) — `ssh-dss` is broken / disabled by
 *                                    default in OpenSSH 7.0+.
 *   - `sshKey.weakRsa`     (error) — RSA modulus < 2048 bits.
 *   - `sshKey.ecdsa.curve` (info)  — ECDSA P-256/384/521 is recognised; we
 *                                    surface the curve name so users can
 *                                    cross-check against site policy.
 */
export function evaluateSshKey(key: DecodedSshKey): Finding[] {
  const findings: Finding[] = []

  if (key.type === 'ssh-dss') {
    findings.push({
      id: 'sshKey.weakDsa',
      severity: 'error',
      message:
        'DSA (ssh-dss) SSH keys are weak and have been disabled by default in OpenSSH 7.0+. Regenerate with `ssh-keygen -t ed25519` or `ssh-keygen -t rsa -b 4096`.',
      docUrl: RFC_4253_URL,
    })
  }

  if (key.type === 'ssh-rsa' && typeof key.modulusBits === 'number' && key.modulusBits < 2048) {
    findings.push({
      id: 'sshKey.weakRsa',
      severity: 'error',
      message: `RSA SSH key is ${key.modulusBits} bits — below the 2048-bit minimum. Regenerate with \`ssh-keygen -t rsa -b 4096\` or switch to Ed25519.`,
      docUrl: RFC_4253_URL,
    })
  }

  if (key.curve) {
    findings.push({
      id: 'sshKey.ecdsa.curve',
      severity: 'info',
      message: `ECDSA SSH key uses curve ${key.curve}.`,
      docUrl: RFC_4253_URL,
    })
  }

  return findings
}
