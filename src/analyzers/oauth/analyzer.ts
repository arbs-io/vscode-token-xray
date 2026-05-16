import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { findTokens, TokenMatchInfo } from './tokenPatterns'

export class OAuthTokenAnalyzer implements Analyzer {
  readonly id = 'oauth'
  readonly name = 'Vendor API token (GitHub / Slack / Stripe / …)'

  detect(text: string): Match[] {
    return findTokens(text).map((hit) => ({
      text: hit.text,
      range: { start: hit.start, end: hit.end },
    }))
  }

  analyze(match: Match): AnalysisResult {
    const hits = findTokens(match.text)
    const primary = hits[0]
    if (!primary) {
      throw new Error('No known vendor token pattern matched.')
    }
    const sections: Section[] = [{ id: 'token', title: 'Token', rows: rowsFor(primary) }]
    const findings: Finding[] = [findingFor(primary)]
    return {
      analyzerId: this.id,
      kind: primary.pattern.vendor,
      sections,
      findings,
      raw: { vendor: primary.pattern.vendor, kind: primary.pattern.kind },
    }
  }
}

function rowsFor(hit: TokenMatchInfo): SectionRow[] {
  const rows: SectionRow[] = [
    { key: 'vendor', value: hit.pattern.vendor, description: 'Issuing service' },
    { key: 'kind', value: hit.pattern.kind, description: 'Token type' },
    { key: 'prefix', value: hit.text.split(/[-_]/, 1)[0], description: 'Vendor prefix' },
    { key: 'length', value: hit.text.length, description: 'Token length (characters)' },
  ]
  if (hit.pattern.environment) {
    rows.push({
      key: 'environment',
      value: hit.pattern.environment,
      description: hit.pattern.environment === 'live' ? 'LIVE / production' : 'test / sandbox',
    })
  }
  return rows
}

function findingFor(hit: TokenMatchInfo): Finding {
  return {
    id: `oauth.${hit.pattern.id}`,
    severity: hit.pattern.severity,
    message: hit.pattern.description,
    docUrl: hit.pattern.docUrl,
  }
}
