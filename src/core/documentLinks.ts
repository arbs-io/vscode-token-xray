import { AnalysisResult } from './types'

/**
 * Range describing where a token was detected, in zero-based line/column
 * coordinates. Mirrors the shape produced by `scanDocument` so the
 * provider adapter can pass `DetectedToken` instances through unchanged.
 */
export interface HitRange {
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
}

/**
 * Plain-data document link emitted by the pure helper. The vscode-aware
 * provider adapter converts this into an actual `vscode.DocumentLink`.
 */
export interface DocumentLinkDto {
  target: string
  range: HitRange
}

/**
 * Pure extractor that lifts URL targets out of an `AnalysisResult` so
 * the provider adapter can render them as clickable links inside the
 * source document.
 *
 * Two sources contribute links, both anchored to the full hit range:
 *
 *   1. Every `Finding.docUrl` in `result.findings` — these are the
 *      remediation links the analyzers attach to their findings (e.g. the
 *      IdP issuer-recognition table or the OAuth provider docs).
 *   2. Every section row whose `key === 'iss'` with an `https://`
 *      string value — the issuer claim itself is usually a useful link
 *      back to the IdP's discovery / well-known endpoint.
 *
 * URL extraction inside the raw token text isn't worth attempting at
 * this layer — the underlying text is base64-encoded for most analyzers,
 * so coarse hit-range anchoring is fine. The provider can decide how
 * tightly to render the link in the editor.
 *
 * Identical `(target, range)` pairs are deduplicated so a finding whose
 * `docUrl` matches another finding's `docUrl` doesn't render twice.
 */
function collectIssuerLinks(result: AnalysisResult): string[] {
  const urls: string[] = []
  for (const section of result.sections ?? []) {
    for (const row of section.rows ?? []) {
      if (row.key !== 'iss') continue
      const value = row.value
      if (typeof value === 'string' && value.startsWith('https://')) urls.push(value)
    }
  }
  return urls
}

export function extractDocumentLinks(
  result: AnalysisResult,
  hitRange: HitRange,
  // The raw token text is intentionally accepted but unused at this layer:
  // URL extraction inside opaque token bodies is left for a future
  // enhancement. Keeping the parameter in the signature makes it
  // forward-compatible.
  _rawText: string
): DocumentLinkDto[] {
  if (!result || !hitRange) return []

  const out: DocumentLinkDto[] = []
  const seen = new Set<string>()
  const push = (target: string) => {
    if (!target) return
    const key = `${target}|${hitRange.startLine}:${hitRange.startColumn}-${hitRange.endLine}:${hitRange.endColumn}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ target, range: { ...hitRange } })
  }

  for (const finding of result.findings ?? []) {
    if (typeof finding.docUrl === 'string') push(finding.docUrl)
  }
  for (const url of collectIssuerLinks(result)) push(url)

  return out
}
