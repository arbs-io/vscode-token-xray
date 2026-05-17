import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { findingsForSigv4 } from './findings'
import { parseSigv4Authorization, Sigv4Components } from './parser'

/**
 * Header-prefixed form:
 *   `Authorization: AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…`
 *
 * The match runs greedy across the rest of the header value until a newline
 * (or end of input). The regex deliberately does NOT validate the inner
 * structure — that is parser.ts's job — so we get a single uniform path for
 * surfacing findings on malformed but recognisable headers.
 */
const HEADER_REGEX = /Authorization\s*[:=]\s*AWS4-HMAC-SHA256\s+[^\r\n]+/gi

/**
 * Standalone form (no `Authorization:` prefix): a single line that starts with
 * `AWS4-HMAC-SHA256` AND contains both `Credential=` and `Signature=` later
 * on the same line. The leading anchor uses `(?:^|[\s,])` so the algorithm
 * token can begin the buffer, follow whitespace, or follow a comma (matches
 * snippet styles used in AWS docs / debug logs).
 *
 * `SignedHeaders=` is enforced via a separate substring check below to keep
 * the regex itself simple (regex alternation around three required tokens in
 * any order would be ugly; explicit checks are easier to read).
 */
const STANDALONE_REGEX = /(?:^|[\s,])(AWS4-HMAC-SHA256\s+[^\r\n]+)/gi

interface InternalHit {
  text: string
  range: { start: number; end: number }
}

function findInternalHits(text: string): InternalHit[] {
  if (!text) return []
  const hits: InternalHit[] = []
  const claimed: Array<{ start: number; end: number }> = []

  const claim = (start: number, end: number): boolean => {
    for (const c of claimed) {
      if (start < c.end && c.start < end) return false
    }
    claimed.push({ start, end })
    return true
  }

  HEADER_REGEX.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = HEADER_REGEX.exec(text)) !== null) {
    const start = m.index
    const end = start + m[0].length
    if (!claim(start, end)) continue
    if (!parseSigv4Authorization(m[0])) continue
    hits.push({ text: m[0], range: { start, end } })
  }

  STANDALONE_REGEX.lastIndex = 0
  while ((m = STANDALONE_REGEX.exec(text)) !== null) {
    const inner = m[1]
    const start = m.index + (m[0].length - inner.length)
    const end = start + inner.length
    if (!claim(start, end)) continue
    // Require all three SigV4 markers on the same line — the spec explicitly
    // calls this out for the standalone form.
    if (!/\bCredential\s*=/.test(inner)) continue
    if (!/\bSignedHeaders\s*=/.test(inner)) continue
    if (!/\bSignature\s*=/.test(inner)) continue
    if (!parseSigv4Authorization(inner)) continue
    hits.push({ text: inner, range: { start, end } })
  }

  hits.sort((a, b) => a.range.start - b.range.start)
  return hits
}

function truncateSignature(signature: string): string {
  if (signature.length <= 8) return signature
  return `${signature.slice(0, 8)}…`
}

function extractValue(text: string): string {
  // Caller may pass a wider context line (e.g. the whole `Authorization:`
  // header). Trim the prefix so parser.ts sees a clean value.
  return text.replace(/^\s*Authorization\s*[:=]\s*/i, '').trim()
}

export class AwsSigv4Analyzer implements Analyzer {
  readonly id = 'awsSigv4'
  readonly name = 'AWS Signature v4'

  detect(text: string): Match[] {
    return findInternalHits(text).map((hit) => ({ text: hit.text, range: hit.range }))
  }

  analyze(match: Match): AnalysisResult {
    const value = extractValue(match.text)
    const components = parseSigv4Authorization(value)
    if (!components) {
      throw new Error('Input does not look like an AWS SigV4 Authorization header.')
    }
    return buildResult(this.id, components)
  }
}

function buildResult(analyzerId: string, components: Sigv4Components): AnalysisResult {
  const rows: SectionRow[] = [
    { key: 'accessKeyId', value: components.accessKeyId, description: 'AWS access key id (plaintext in the SigV4 header).' },
    { key: 'region', value: components.region, description: 'AWS region from the credential scope.' },
    { key: 'service', value: components.service, description: 'AWS service from the credential scope.' },
    { key: 'date', value: components.date, description: 'Request date (YYYYMMDD) from the credential scope.' },
    { key: 'signedHeaders', value: components.signedHeaders.join(';'), description: 'Headers included in the canonical request signature.' },
    { key: 'signature', value: truncateSignature(components.signature), description: 'Signature digest (truncated to first 8 characters).' },
  ]
  const sections: Section[] = [{ id: 'signature', title: 'Signature', rows }]
  const findings: Finding[] = findingsForSigv4(components)
  return {
    analyzerId,
    kind: 'AWS SigV4',
    sections,
    findings,
    raw: components,
  }
}
