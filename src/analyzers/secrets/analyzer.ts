import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { BUILT_IN_SECRET_RULES } from './rules'
import { scanForSecrets } from './scanner'
import { SecretHit, SecretRule } from './types'

export class SecretAnalyzer implements Analyzer {
  readonly id = 'secret'
  readonly name = 'Secret / credential'

  constructor(private readonly rules: SecretRule[] = BUILT_IN_SECRET_RULES) {}

  detect(text: string): Match[] {
    return scanForSecrets(text, { rules: this.rules }).map((hit) => ({
      text: hit.text,
      range: { start: hit.start, end: hit.end },
    }))
  }

  analyze(match: Match): AnalysisResult {
    const hits = scanForSecrets(match.text, { rules: this.rules })
    const hit = hits[0]
    if (!hit) {
      throw new Error('No secret rule matched the input.')
    }
    const sections: Section[] = [{ id: 'secret', title: hit.rule.name, rows: rowsFor(hit) }]
    const finding: Finding = {
      id: hit.rule.id,
      severity: hit.rule.severity,
      message: hit.rule.description,
      docUrl: hit.rule.docUrl,
    }
    return {
      analyzerId: this.id,
      kind: hit.rule.vendor,
      sections,
      findings: [finding],
      raw: { ruleId: hit.rule.id, vendor: hit.rule.vendor, length: hit.text.length },
    }
  }
}

function rowsFor(hit: SecretHit): SectionRow[] {
  return [
    { key: 'rule', value: hit.rule.id, description: 'Rule id' },
    { key: 'vendor', value: hit.rule.vendor, description: 'Vendor / category' },
    { key: 'severity', value: hit.rule.severity, description: 'Severity' },
    { key: 'length', value: hit.text.length, description: 'Match length (characters)' },
    { key: 'preview', value: redact(hit), description: 'Preview (redacted)' },
  ]
}

function redact(hit: SecretHit): string {
  const text = hit.text
  if (text.length <= 60) return text.slice(0, 12) + '…'
  return text.slice(0, 30) + '…' + text.slice(-12)
}
