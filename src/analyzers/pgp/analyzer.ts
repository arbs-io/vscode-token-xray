import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { DecodedPgp, decodePgp } from './decoder'
import { evaluatePgp } from './findings'

/**
 * OpenPGP armor analyzer — detects ASCII-armored PGP blocks and
 * surfaces their type, optional Version / Comment headers, and the
 * first OpenPGP packet tag byte.
 *
 * The detector matches the five RFC 9580 block types (PUBLIC/PRIVATE
 * KEY BLOCK, SIGNATURE, MESSAGE, SIGNED MESSAGE) with a backreference
 * so a `BEGIN PGP MESSAGE` must be paired with `END PGP MESSAGE` —
 * mismatched markers don't match. Every regex hit is then validated
 * by `decodePgp()` so malformed blocks still surface (with a finding)
 * but unrelated text never does.
 */
const PGP_BLOCK_REGEX =
  /-----BEGIN PGP (PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE|MESSAGE|SIGNED MESSAGE)-----[\s\S]*?-----END PGP \1-----/g

export class PgpAnalyzer implements Analyzer {
  readonly id = 'pgp'
  readonly name = 'OpenPGP armored block'

  detect(text: string): Match[] {
    if (!text) return []
    const matches: Match[] = []
    PGP_BLOCK_REGEX.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = PGP_BLOCK_REGEX.exec(text)) !== null) {
      const span = m[0]
      if (!decodePgp(span)) continue
      const start = m.index
      const end = start + span.length
      matches.push({ text: span, range: { start, end } })
    }
    return matches
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodePgp(match.text)
    if (!decoded) {
      throw new Error('Input does not look like an OpenPGP armored block.')
    }
    return buildResult(this.id, decoded)
  }
}

function buildResult(analyzerId: string, decoded: DecodedPgp): AnalysisResult {
  const rows: SectionRow[] = [
    {
      key: 'blockType',
      value: decoded.blockType,
      description: 'OpenPGP armored block type (RFC 9580 §6).',
    },
  ]

  if (decoded.headers['Version']) {
    rows.push({
      key: 'version',
      value: decoded.headers['Version'],
      description: 'Implementation that produced the block (Version armor header).',
    })
  }

  if (decoded.headers['Comment']) {
    rows.push({
      key: 'comment',
      value: decoded.headers['Comment'],
      description: 'Free-form note attached to the armored block (Comment armor header).',
    })
  }

  if (typeof decoded.firstPacketTag === 'number') {
    rows.push({
      key: 'firstPacketTag',
      value: formatHex(decoded.firstPacketTag),
      description:
        'First byte of the decoded body — RFC 4880 §4.2 packet header tag (bit 7 = 1 always; bit 6 = 1 for new-format packets).',
    })
  }

  const sections: Section[] = [{ id: 'block', title: 'Block', rows }]
  const findings: Finding[] = evaluatePgp(decoded)

  return {
    analyzerId,
    kind: kindFor(decoded.blockType),
    sections,
    findings,
    raw: decoded,
  }
}

function kindFor(blockType: DecodedPgp['blockType']): string {
  switch (blockType) {
    case 'PUBLIC KEY BLOCK':
      return 'OpenPGP public key'
    case 'PRIVATE KEY BLOCK':
      return 'OpenPGP private key'
    case 'SIGNATURE':
      return 'OpenPGP signature'
    case 'MESSAGE':
      return 'OpenPGP encrypted message'
    case 'SIGNED MESSAGE':
      return 'OpenPGP cleartext-signed message'
  }
}

function formatHex(byte: number): string {
  return '0x' + byte.toString(16).padStart(2, '0').toUpperCase()
}
