import { Finding, Section } from './types'

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
 * Subset of a detected hit shape that the pure mapper needs. The provider
 * adapter assembles this from a `DetectedToken` plus the first analyzer
 * section so the mapper can stay vscode-free.
 */
export interface DocumentSymbolHit {
  analyzerId: string
  analyzerName: string
  /** Optional analyzer-supplied kind string (e.g. `'JWS'`, `'PASETO v4.public'`). */
  kind?: string
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
  /** First (most descriptive) analyzer section, used to derive the symbol name. */
  firstSection?: Section
  /** Optional findings list, used to compose the detail string. */
  findings?: readonly Finding[]
}

/**
 * Plain-data document symbol emitted by the pure mapper. The vscode-aware
 * provider adapter converts this into an actual `vscode.DocumentSymbol`.
 *
 * `kind` is a stringly-typed enum mirroring a sensible subset of
 * `vscode.SymbolKind` — keeping it as a string keeps the helper free of
 * vscode imports. The provider adapter maps each value to the matching
 * `SymbolKind` member at the adapter boundary.
 */
export interface DocumentSymbolDto {
  name: string
  detail?: string
  kind: DocumentSymbolKind
  range: HitRange
  selectionRange: HitRange
}

export type DocumentSymbolKind = 'Key' | 'Constant' | 'Object' | 'String'

/** Maximum length of the rendered symbol name. Longer names get truncated. */
export const MAX_SYMBOL_NAME_LENGTH = 60

/**
 * Analyzer ids whose detected tokens are best represented as `Constant`
 * symbols (immutable identifiers / fingerprints / secrets).
 */
const CONSTANT_KIND_IDS = new Set<string>([
  'x509',
  'paseto',
  'jwk',
  'cookie',
  'secret',
])

/**
 * Analyzer ids whose detected tokens behave more like structured
 * documents — they fan out into multiple sections that mirror an
 * object's properties.
 */
const OBJECT_KIND_IDS = new Set<string>([
  'saml',
  'oidcDiscovery',
  'samlMetadata',
])

/**
 * Pure mapper from a list of analyzer hits to a list of outline-entry
 * DTOs. The provider adapter calls this with the result of
 * `scanDocument` (augmented with each hit's first analyzer section and
 * findings), then converts the resulting DTOs to
 * `vscode.DocumentSymbol[]` for VS Code's outline panel.
 *
 * The function never throws and never reads from anything but the
 * provided hits.
 */
export function buildDocumentSymbolDtos(hits: readonly DocumentSymbolHit[]): DocumentSymbolDto[] {
  if (!hits || hits.length === 0) return []
  const out: DocumentSymbolDto[] = []
  for (const hit of hits) {
    if (!hit) continue
    out.push(buildOne(hit))
  }
  return out
}

function buildOne(hit: DocumentSymbolHit): DocumentSymbolDto {
  const range: HitRange = {
    startLine: hit.startLine,
    startColumn: hit.startColumn,
    endLine: hit.endLine,
    endColumn: hit.endColumn,
  }
  return {
    name: buildName(hit),
    detail: buildDetail(hit.findings),
    kind: pickKind(hit.analyzerId),
    range,
    selectionRange: { ...range },
  }
}

function buildName(hit: DocumentSymbolHit): string {
  const firstValue = firstRowValue(hit.firstSection)
  const valueLabel = firstValue ?? 'token'
  const raw = `${hit.analyzerName}: ${valueLabel}`
  if (raw.length <= MAX_SYMBOL_NAME_LENGTH) return raw
  return raw.slice(0, MAX_SYMBOL_NAME_LENGTH - 1).trimEnd() + '…'
}

function firstRowValue(section: Section | undefined): string | undefined {
  if (!section) return undefined
  const rows = section.rows
  if (!rows || rows.length === 0) return undefined
  const value = rows[0].value
  if (value === undefined || value === null) return undefined
  if (typeof value === 'string') {
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : undefined
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value)
  }
  // Anything else (object / array) is JSON-serialised so the outline still
  // shows something meaningful. Falls back to `[unrenderable]` when
  // serialisation throws (circular refs etc.).
  try {
    return JSON.stringify(value)
  } catch {
    return '[unrenderable]'
  }
}

function buildDetail(findings: readonly Finding[] | undefined): string | undefined {
  if (!findings || findings.length === 0) return undefined
  let errors = 0
  let warnings = 0
  for (const finding of findings) {
    if (finding.severity === 'error') errors++
    else if (finding.severity === 'warning') warnings++
  }
  const total = findings.length
  const plural = total === 1 ? 'finding' : 'findings'
  const parts: string[] = []
  if (errors > 0) parts.push(`${errors} ${errors === 1 ? 'error' : 'errors'}`)
  if (warnings > 0) parts.push(`${warnings} ${warnings === 1 ? 'warning' : 'warnings'}`)
  if (parts.length === 0) return `${total} ${plural}`
  return `${total} ${plural} (${parts.join(', ')})`
}

function pickKind(analyzerId: string): DocumentSymbolKind {
  if (!analyzerId) return 'String'
  if (CONSTANT_KIND_IDS.has(analyzerId)) return 'Constant'
  if (OBJECT_KIND_IDS.has(analyzerId)) return 'Object'
  return 'Key'
}
