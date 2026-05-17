import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import { decodeJwkInput, DecodedJwk, looksLikeJwkJson } from './decoder'
import { evaluateJwk } from './findings'

export class JwkAnalyzer implements Analyzer {
  readonly id = 'jwk'
  readonly name = 'JSON Web Key (JWK / JWKS)'

  detect(text: string): Match[] {
    if (!text) return []
    const trimmed = text.trim()
    if (!looksLikeJwkJson(trimmed)) return []
    try {
      decodeJwkInput(trimmed)
    } catch {
      return []
    }
    const start = text.indexOf(trimmed)
    return [{ text: trimmed, range: { start: Math.max(start, 0), end: text.length } }]
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeJwkInput(match.text)
    const findings = evaluateJwk(decoded)

    const sections: Section[] =
      decoded.kind === 'jwk' ? [keySection(decoded.key, 0)] : decoded.keys.map((k, i) => keySection(k, i))

    return {
      analyzerId: this.id,
      kind: decoded.kind === 'jwks' ? 'JWKS' : 'JWK',
      sections,
      findings,
      raw: decoded,
    }
  }
}

function keySection(key: DecodedJwk, index: number): Section {
  const rows: SectionRow[] = [
    { key: 'kty', value: key.kty, description: 'Key type' },
  ]
  if (key.kid) rows.push({ key: 'kid', value: key.kid, description: 'Key ID' })
  if (key.use) rows.push({ key: 'use', value: key.use, description: 'Public-key use (sig | enc)' })
  if (key.alg) rows.push({ key: 'alg', value: key.alg, description: 'Algorithm' })
  if (key.curve) rows.push({ key: 'crv', value: key.curve, description: 'Curve' })
  if (key.keySizeBits !== undefined) {
    rows.push({ key: 'keySizeBits', value: key.keySizeBits, description: 'Key size (bits)' })
  }
  if (key.keyOps?.length) {
    rows.push({ key: 'key_ops', value: key.keyOps.join(', '), description: 'Key operations' })
  }
  if (key.hasPrivateMaterial) {
    rows.push({ key: 'privateMaterial', value: 'true', description: 'Includes private components' })
  }
  return { id: `key-${index}`, title: `Key #${index + 1} (${key.kty})`, rows }
}
