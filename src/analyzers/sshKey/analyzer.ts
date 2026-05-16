import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { DecodedSshKey, decodeSshKey } from './decoder'
import { evaluateSshKey } from './findings'

/**
 * OpenSSH public-key analyzer — detects and surfaces RSA / Ed25519 /
 * ECDSA (P-256/384/521) / DSA public keys on a single line.
 *
 * The detector is a coarse regex (any of the supported algorithm names
 * followed by a base64 body and optional comment); every hit is then
 * validated by running `decodeSshKey()` against the matched text — only
 * lines whose embedded type string matches the prefix survive. This
 * keeps false positives close to zero without having to do the full
 * parse twice.
 */
const SSH_KEY_REGEX =
  /(?<![A-Za-z0-9-])(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]+={0,2}(?:\s+[^\r\n]+)?/g

export class SshKeyAnalyzer implements Analyzer {
  readonly id = 'sshKey'
  readonly name = 'OpenSSH public key'

  detect(text: string): Match[] {
    if (!text) return []
    const matches: Match[] = []
    SSH_KEY_REGEX.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = SSH_KEY_REGEX.exec(text)) !== null) {
      const span = m[0]
      if (!decodeSshKey(span)) continue
      const start = m.index
      const end = start + span.length
      matches.push({ text: span, range: { start, end } })
    }
    return matches
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeSshKey(match.text)
    if (!decoded) {
      throw new Error('Input does not look like a supported OpenSSH public key.')
    }
    return buildResult(this.id, decoded)
  }
}

function buildResult(analyzerId: string, decoded: DecodedSshKey): AnalysisResult {
  const rows: SectionRow[] = [
    { key: 'type', value: decoded.type, description: 'OpenSSH public-key algorithm identifier.' },
  ]
  if (decoded.comment) {
    rows.push({ key: 'comment', value: decoded.comment, description: 'Trailing comment (often the host or user label).' })
  }
  if (typeof decoded.modulusBits === 'number') {
    rows.push({ key: 'modulusBits', value: decoded.modulusBits, description: 'RSA modulus bit length.' })
  }
  if (decoded.curve) {
    rows.push({ key: 'curve', value: decoded.curve, description: 'ECDSA named curve.' })
  }

  const sections: Section[] = [{ id: 'key', title: 'Key', rows }]
  const findings: Finding[] = evaluateSshKey(decoded)

  return {
    analyzerId,
    kind: 'OpenSSH public key',
    sections,
    findings,
    raw: decoded,
  }
}
