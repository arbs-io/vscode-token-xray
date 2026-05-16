import { Finding } from '../../core/types'
import { BUILT_IN_SECRET_RULES } from './rules'
import { SecretHit, SecretRule, SecretRuleContext } from './types'

export interface ScanOptions {
  rules?: SecretRule[]
  context?: SecretRuleContext
  maxBytes?: number
}

export function scanForSecrets(text: string, options: ScanOptions = {}): SecretHit[] {
  if (!text) return []
  const max = options.maxBytes ?? 1_000_000
  if (text.length > max) return []
  const rules = options.rules ?? BUILT_IN_SECRET_RULES
  const ctx = options.context ?? {}
  const hits: SecretHit[] = []

  for (const rule of rules) {
    rule.pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = rule.pattern.exec(text)) !== null) {
      const raw = m[0]
      if (raw.length === 0) {
        rule.pattern.lastIndex++
        continue
      }
      if (rule.validate && !rule.validate(raw, ctx)) continue
      const span = rule.sensitiveSpan ? rule.sensitiveSpan(raw) : { start: 0, end: raw.length }
      hits.push({
        rule,
        text: raw,
        start: m.index,
        end: m.index + raw.length,
        sensitiveStart: m.index + span.start,
        sensitiveEnd: m.index + span.end,
      })
    }
  }

  return dedupe(hits)
}

export function findingsForSecrets(text: string, options: ScanOptions = {}): Finding[] {
  return scanForSecrets(text, options).map((hit) => ({
    id: hit.rule.id,
    severity: hit.rule.severity,
    message: `${hit.rule.name} — ${hit.rule.description}`,
    docUrl: hit.rule.docUrl,
    range: { start: hit.sensitiveStart, end: hit.sensitiveEnd },
  }))
}

function dedupe(hits: SecretHit[]): SecretHit[] {
  hits.sort((a, b) => a.start - b.start || b.end - a.end)
  // Pass 1: drop same-rule overlapping hits (existing behaviour).
  const sameRuleDeduped: SecretHit[] = []
  for (const hit of hits) {
    const last = sameRuleDeduped[sameRuleDeduped.length - 1]
    if (last && hit.rule.id === last.rule.id && hit.start < last.end) continue
    sameRuleDeduped.push(hit)
  }
  // Pass 2: drop info-severity hits whose range overlaps any
  // higher-severity hit from a different rule. This lets the generic
  // high-entropy rule coexist with specific vendor rules without
  // double-flagging the same string.
  const result: SecretHit[] = []
  for (const hit of sameRuleDeduped) {
    if (hit.rule.severity === 'info' && overlapsHigherSeverity(hit, sameRuleDeduped)) continue
    result.push(hit)
  }
  return result
}

function overlapsHigherSeverity(target: SecretHit, all: SecretHit[]): boolean {
  for (const other of all) {
    if (other === target) continue
    if (other.rule.id === target.rule.id) continue
    if (other.rule.severity === 'info') continue
    if (other.start < target.end && target.start < other.end) return true
  }
  return false
}
