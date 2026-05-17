import { Finding } from '../../core/types'
import { BUILT_IN_SECRET_RULES } from './rules'
import { SecretHit, SecretRule, SecretRuleContext } from './types'

export interface ScanOptions {
  rules?: SecretRule[]
  context?: SecretRuleContext
  maxBytes?: number
}

// Regions where the generic high-entropy rule produces pure noise because the
// content is already a structured-token shape another analyzer handles:
//   - PEM armor blocks (certs, public keys, CSRs, PGP messages, OpenSSH, ...).
//     The PEM PRIVATE KEY rule covers the same region with `error` severity so
//     it's already suppressed by the cross-rule dedup, but cert / public-key
//     PEMs aren't secret-rule-covered at all and used to emit one info hit per
//     base64 body line.
//   - JWT / JWS / JWE shapes: three (or five) `.`-separated base64url segments
//     embedded in source code. Each segment hits the entropy threshold on its
//     own.
const PEM_BLOCK_RE = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g
const JWT_SHAPE_RE = /\beyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]{4,}){2,4}\b/g

function findEntropySuppressionRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = []
  for (const re of [PEM_BLOCK_RE, JWT_SHAPE_RE]) {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      ranges.push([m.index, m.index + m[0].length])
      if (m[0].length === 0) re.lastIndex++
    }
  }
  return ranges
}

function isInsideRange(hit: SecretHit, ranges: Array<[number, number]>): boolean {
  for (const [s, e] of ranges) {
    if (hit.start >= s && hit.end <= e) return true
  }
  return false
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

  const suppressionRanges = findEntropySuppressionRanges(text)
  const filtered = hits.filter((hit) => {
    if (hit.rule.id !== 'secret.generic.highEntropy') return true
    return !isInsideRange(hit, suppressionRanges)
  })

  return dedupe(filtered)
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
