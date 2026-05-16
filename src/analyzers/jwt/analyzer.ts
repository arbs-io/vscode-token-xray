import { Analyzer, AnalysisResult, Match, Section, SectionRow } from '../../core/types'
import { getClaimDefinition } from './claimDefinitions'
import { decodeJwt, detectJwtKind } from './decoder'
import { evaluateJwt, JwtFindingOptions } from './findings'

const JWT_TOKEN_REGEX = /eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*(?:\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+)?/g

export class JwtAnalyzer implements Analyzer {
  readonly id = 'jwt'
  readonly name = 'JSON Web Token (JWT)'

  constructor(private readonly options: JwtFindingOptions = {}) {}

  detect(text: string): Match[] {
    if (!text) return []
    const matches: Match[] = []
    JWT_TOKEN_REGEX.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = JWT_TOKEN_REGEX.exec(text)) !== null) {
      const kind = detectJwtKind(m[0])
      if (kind === 'unknown') continue
      matches.push({ text: m[0], range: { start: m.index, end: m.index + m[0].length } })
    }
    return matches
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeJwt(match.text)
    const findings = evaluateJwt(decoded, this.options)

    const headerSection: Section = {
      id: 'header',
      title: 'JOSE Header',
      rows: Object.entries(decoded.header).map(([key, value]) => buildRow(key, value)),
    }

    const sections: Section[] = [headerSection]

    if (decoded.payload) {
      sections.push({
        id: 'payload',
        title: 'Claims',
        rows: Object.entries(decoded.payload).map(([key, value]) => buildRow(key, value)),
      })
    }

    return {
      analyzerId: this.id,
      kind: decoded.kind,
      sections,
      findings,
      raw: decoded,
    }
  }
}

function buildRow(key: string, value: unknown): SectionRow {
  const def = getClaimDefinition(key)
  let displayValue: unknown = value
  if (def?.isTimestamp && typeof value === 'number') {
    displayValue = `${value} (${new Date(value * 1000).toISOString()})`
  }
  return {
    key,
    value: displayValue,
    description: def?.description,
    iconKey: def?.iconKey,
  }
}
