import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { findingsForCavage, findingsForRfc9421 } from './findings'
import { CavageSig, parseCavageSignature, parseRfc9421, Rfc9421Sig } from './parser'

/**
 * Line-anchored matchers for the two header forms. We capture the full
 * line (up to the first CR/LF) so the candidate can be passed verbatim
 * to the parser — header values are line-oriented in HTTP wire format.
 */
const SIGNATURE_LINE_REGEX = /^[ \t]*Signature\s*[:=][^\r\n]+/gim
const SIGNATURE_INPUT_LINE_REGEX = /^[ \t]*Signature-Input\s*[:=][^\r\n]+/gim

type Variant = 'cavage' | 'rfc9421'

interface InternalHit {
  text: string
  range: { start: number; end: number }
  variant: Variant
  /** For RFC 9421 hits: the matching `Signature:` line, if found. */
  pairedSignatureLine?: string
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

  // Pass 1: collect every `Signature-Input:` line and try to pair each
  // with a `Signature:` line further along the buffer. RFC 9421
  // headers travel as a pair, so we look ahead within the same text
  // and match by label.
  const inputCandidates: Array<{
    line: string
    start: number
    end: number
    label: string
  }> = []
  SIGNATURE_INPUT_LINE_REGEX.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = SIGNATURE_INPUT_LINE_REGEX.exec(text)) !== null) {
    const line = m[0]
    const start = m.index
    const end = start + line.length
    const labelMatch = /Signature-Input\s*[:=]\s*([A-Za-z0-9_-]+)\s*=/i.exec(line)
    if (!labelMatch) continue
    inputCandidates.push({ line, start, end, label: labelMatch[1] })
  }

  // Pass 2: collect every `Signature:` line (excluding `Signature-Input`
  // — the regex is `Signature\s*[:=]` so it would otherwise match
  // both).
  const sigCandidates: Array<{ line: string; start: number; end: number; label?: string }> = []
  SIGNATURE_LINE_REGEX.lastIndex = 0
  while ((m = SIGNATURE_LINE_REGEX.exec(text)) !== null) {
    const line = m[0]
    // Exclude lines that begin with `Signature-Input` — they were
    // already collected above and would otherwise be re-matched.
    if (/^[ \t]*Signature-Input/i.test(line)) continue
    const start = m.index
    const end = start + line.length
    // Capture the leading label for RFC 9421 form (`sig1=:…:`).
    const labelMatch = /Signature\s*[:=]\s*([A-Za-z0-9_-]+)\s*=\s*:/i.exec(line)
    sigCandidates.push({
      line,
      start,
      end,
      label: labelMatch ? labelMatch[1] : undefined,
    })
  }

  // Pair Signature-Input → Signature by label.
  for (const inp of inputCandidates) {
    const partner = sigCandidates.find((s) => s.label === inp.label)
    const parsed = parseRfc9421(inp.line, partner?.line)
    if (!parsed) continue
    if (!claim(inp.start, inp.end)) continue
    if (partner) claim(partner.start, partner.end)
    hits.push({
      text: inp.line,
      range: { start: inp.start, end: inp.end },
      variant: 'rfc9421',
      pairedSignatureLine: partner?.line,
    })
  }

  // Remaining (unclaimed) `Signature:` lines: try the Cavage parser.
  for (const sig of sigCandidates) {
    if (!claim(sig.start, sig.end)) continue
    const parsed = parseCavageSignature(sig.line)
    if (!parsed) {
      // Roll back the claim so a future analyzer pass on this text
      // doesn't see a phantom block.
      claimed.pop()
      continue
    }
    hits.push({
      text: sig.line,
      range: { start: sig.start, end: sig.end },
      variant: 'cavage',
    })
  }

  hits.sort((a, b) => a.range.start - b.range.start)
  return hits
}

function truncate(signature: string): string {
  if (signature.length <= 16) return signature
  return `${signature.slice(0, 16)}…`
}

function detectVariant(text: string): Variant {
  // A line beginning with `Signature-Input` (case-insensitive) is
  // unambiguously RFC 9421. Otherwise we treat it as Cavage and let
  // the parser confirm or reject.
  return /^[ \t]*Signature-Input\b/im.test(text) ? 'rfc9421' : 'cavage'
}

export class HttpSignatureAnalyzer implements Analyzer {
  readonly id = 'httpSignature'
  readonly name = 'HTTP Signature'

  detect(text: string): Match[] {
    return findInternalHits(text).map((hit) => ({ text: hit.text, range: hit.range }))
  }

  analyze(match: Match): AnalysisResult {
    const variant = detectVariant(match.text)
    if (variant === 'rfc9421') {
      // The inspect command may pass several joined lines (the
      // `Signature-Input:` line plus the matching `Signature:` line).
      // Split them apart so the parser sees a clean `Signature-Input`
      // value and we can pair the partner explicitly.
      const inputLine = extractSignatureInputLine(match.text) ?? match.text
      const partner = extractPartnerSignatureLine(match.text)
      const parsed = parseRfc9421(inputLine, partner)
      if (!parsed) {
        throw new Error('Input does not look like an RFC 9421 HTTP signature.')
      }
      return buildRfc9421Result(this.id, parsed)
    }

    const parsed = parseCavageSignature(match.text)
    if (!parsed) {
      throw new Error('Input does not look like a Cavage HTTP signature header.')
    }
    return buildCavageResult(this.id, parsed)
  }
}

/**
 * Pull the first `Signature-Input:` line out of a multi-line buffer.
 * Returns `undefined` when the buffer is already a single line.
 */
function extractSignatureInputLine(text: string): string | undefined {
  if (!/\r?\n/.test(text)) return undefined
  for (const line of text.split(/\r?\n/)) {
    if (/^[ \t]*Signature-Input\s*[:=]/i.test(line)) return line
  }
  return undefined
}

/**
 * The inspect command may pass a wider context (e.g. two lines joined
 * by `\n` containing both the `Signature-Input` and `Signature` lines).
 * Pull out the `Signature:` line if present so the parser can extract
 * the base64 blob.
 */
function extractPartnerSignatureLine(text: string): string | undefined {
  const lines = text.split(/\r?\n/)
  for (const line of lines) {
    if (/^[ \t]*Signature\s*[:=]/i.test(line) && !/^[ \t]*Signature-Input/i.test(line)) {
      return line
    }
  }
  return undefined
}

function buildCavageResult(analyzerId: string, sig: CavageSig): AnalysisResult {
  const rows: SectionRow[] = [
    { key: 'variant', value: 'Cavage (draft-cavage-http-signatures)', description: 'Detected signature header dialect.' },
    { key: 'keyId', value: sig.keyId, description: 'Opaque key identifier the verifier uses to locate the public key / shared secret.' },
  ]
  if (sig.algorithm) {
    rows.push({ key: 'algorithm', value: sig.algorithm, description: 'Signature algorithm declared in the header.' })
  }
  if (sig.headers && sig.headers.length > 0) {
    rows.push({ key: 'headers', value: sig.headers.join(' '), description: 'Headers covered by the signature (space-separated).' })
  }
  if (sig.created !== undefined) {
    rows.push({ key: 'created', value: sig.created, description: 'Signature creation time (Unix seconds).' })
  }
  if (sig.expires !== undefined) {
    rows.push({ key: 'expires', value: sig.expires, description: 'Signature expiry time (Unix seconds).' })
  }
  rows.push({
    key: 'signature',
    value: truncate(sig.signature),
    description: 'Signature blob (truncated to the first 16 characters).',
  })

  const sections: Section[] = [{ id: 'signature', title: 'Signature', rows }]
  const findings: Finding[] = findingsForCavage(sig)
  return {
    analyzerId,
    kind: 'HTTP Signature (Cavage)',
    sections,
    findings,
    raw: sig,
  }
}

function buildRfc9421Result(analyzerId: string, sig: Rfc9421Sig): AnalysisResult {
  const rows: SectionRow[] = [
    { key: 'variant', value: 'RFC 9421', description: 'Detected signature header dialect.' },
    { key: 'label', value: sig.label, description: 'Signature label as defined in the Signature-Input header.' },
  ]
  if (sig.keyId) {
    rows.push({ key: 'keyId', value: sig.keyId, description: 'Key reference for the verifier.' })
  }
  if (sig.algorithm) {
    rows.push({ key: 'algorithm', value: sig.algorithm, description: 'Signature algorithm (carried inline; RFC 9421 discourages this).' })
  }
  rows.push({ key: 'components', value: sig.components.join(' '), description: 'Covered components and headers (space-separated).' })
  if (sig.created !== undefined) {
    rows.push({ key: 'created', value: sig.created, description: 'Signature creation time (Unix seconds).' })
  }
  if (sig.expires !== undefined) {
    rows.push({ key: 'expires', value: sig.expires, description: 'Signature expiry time (Unix seconds).' })
  }
  if (sig.nonce) {
    rows.push({ key: 'nonce', value: sig.nonce, description: 'Per-signature nonce.' })
  }
  if (sig.signature) {
    rows.push({
      key: 'signature',
      value: truncate(sig.signature),
      description: 'Signature blob from the paired Signature header (truncated to the first 16 characters).',
    })
  }

  const sections: Section[] = [{ id: 'signature', title: 'Signature', rows }]
  const findings: Finding[] = findingsForRfc9421(sig)
  return {
    analyzerId,
    kind: 'HTTP Signature (RFC 9421)',
    sections,
    findings,
    raw: sig,
  }
}
