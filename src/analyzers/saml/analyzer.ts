import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import { decodeSaml, looksLikeSamlXml } from './decoder'
import { evaluateSaml, SamlFindingOptions } from './findings'

export class SamlAnalyzer implements Analyzer {
  readonly id = 'saml'
  readonly name = 'SAML 2.0 (assertion / response)'

  constructor(private readonly options: SamlFindingOptions = {}) {}

  detect(text: string): Match[] {
    if (!text) return []
    const trimmed = text.trim()
    if (looksLikeSamlXml(trimmed)) {
      const start = text.indexOf(trimmed)
      return [{ text: trimmed, range: { start: Math.max(start, 0), end: text.length } }]
    }
    const matches: Match[] = []
    const elementRegex = /<((?:saml|samlp)?:?)(Response|Assertion|EncryptedAssertion)\b[^>]*>[\s\S]*?<\/\1\2>/g
    let m: RegExpExecArray | null
    while ((m = elementRegex.exec(text)) !== null) {
      matches.push({ text: m[0], range: { start: m.index, end: m.index + m[0].length } })
    }
    if (matches.length > 0) return matches
    if (/^[A-Za-z0-9+/=_\-%]+$/.test(trimmed) && trimmed.length > 64) {
      try {
        decodeSaml(trimmed)
        return [{ text: trimmed, range: { start: 0, end: text.length } }]
      } catch {
        return []
      }
    }
    return []
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeSaml(match.text)
    const findings = evaluateSaml(decoded, this.options)

    const overview: SectionRow[] = [
      { key: 'kind', value: decoded.kind, description: 'SAML element kind' },
    ]
    if (decoded.issuer) overview.push({ key: 'issuer', value: decoded.issuer, description: 'Identity Provider' })
    if (decoded.subject?.nameId) {
      overview.push({
        key: 'subject',
        value: decoded.subject.nameId,
        description: decoded.subject.nameIdFormat ?? 'NameID',
      })
    }
    if (decoded.conditions?.notBefore) {
      overview.push({ key: 'notBefore', value: decoded.conditions.notBefore, description: 'Valid from' })
    }
    if (decoded.conditions?.notOnOrAfter) {
      overview.push({
        key: 'notOnOrAfter',
        value: decoded.conditions.notOnOrAfter,
        description: 'Valid until (exclusive)',
      })
    }
    if (decoded.conditions?.audiences.length) {
      overview.push({
        key: 'audience',
        value: decoded.conditions.audiences.join(', '),
        description: 'AudienceRestriction',
      })
    }
    overview.push({
      key: 'signature',
      value: decoded.signature.present ? `present (${decoded.signature.algorithm ?? 'unknown alg'})` : 'absent',
      description: 'Signature',
    })
    if (decoded.isEncrypted) {
      overview.push({ key: 'encrypted', value: 'true', description: 'EncryptedAssertion' })
    }

    const sections: Section[] = [
      { id: 'overview', title: 'SAML Overview', rows: overview },
    ]

    return {
      analyzerId: this.id,
      kind: decoded.kind,
      sections,
      findings,
      raw: decoded,
    }
  }
}
