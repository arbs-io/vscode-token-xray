import { Finding, Severity } from './types'
import { AnalyzerRegistry } from './registry'
import { applyDisableComments, FindingWithLocation } from './disableComments'
import { applySeverityOverrides, SeverityOverrideMap } from './severityOverrides'

export type DiagnosticSeverityDto = 'error' | 'warning' | 'information' | 'hint'

export interface DiagnosticRangeDto {
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
}

export interface DiagnosticDto {
  message: string
  severity: DiagnosticSeverityDto
  source: string
  code: string
  range: DiagnosticRangeDto
}

const SEVERITY_MAP: Record<Severity, DiagnosticSeverityDto> = {
  error: 'error',
  warning: 'warning',
  info: 'information',
}

export function findingToDiagnostic(
  finding: Finding,
  source: string,
  range: DiagnosticRangeDto
): DiagnosticDto {
  return {
    message: finding.message,
    severity: SEVERITY_MAP[finding.severity],
    source,
    code: finding.id,
    range,
  }
}

/**
 * One suppression event emitted by `diagnosticsAcrossRegistry` for
 * every finding dropped by either of the two registry-boundary
 * filters. The `reason` discriminator lets the provider format a
 * human-readable line per event; `findingId` + `startLine` give
 * enough context to pinpoint the source in the user's document.
 *
 * Pure data — no vscode references — so the core stays
 * provider-agnostic.
 */
export interface SuppressionEvent {
  reason: 'severityOverride' | 'inlineDisableComment'
  findingId: string
  analyzerId: string
  startLine: number
}

/**
 * Aggregate counters surfaced after the registry-boundary filters run.
 * All four values are derived from the pre-existing `pending` /
 * `overridden` / `kept` arrays inside `diagnosticsAcrossRegistry` — no
 * new counters are introduced. The callback fires exactly once per
 * call so providers can log a single summary line per refresh.
 */
export interface DiagnosticsMetrics {
  /** Total findings produced by analyzers before any filtering. */
  scanned: number
  /** Findings dropped because `tokenXray.ruleSeverity` resolved to `off`. */
  droppedBySeverityOverride: number
  /** Findings dropped by inline `tokenxray-disable-*` directives. */
  droppedByDisableComments: number
}

/** Optional knobs honoured by `diagnosticsAcrossRegistry`. */
export interface DiagnosticsAcrossRegistryOptions {
  /**
   * User-configured per-rule severity overrides. Applied at the registry
   * boundary BEFORE `applyDisableComments` so an `off` override is
   * honoured even when no inline disable directive is present.
   */
  ruleSeverity?: SeverityOverrideMap
  /**
   * Optional per-suppression sink. Invoked once for every finding the
   * severity-override pass and the inline-disable-comments pass drop.
   * The callback runs synchronously inside the filter loop; consumers
   * should keep it cheap (the debug logger short-circuits when the
   * `tokenXray.debug` setting is false). The core never throws — a
   * throwing callback is its own caller's bug.
   */
  onSuppression?: (event: SuppressionEvent) => void
  /**
   * Optional aggregate-metrics sink invoked exactly once per call,
   * after both filters have run. Carries the scanned-tokens count and
   * the two suppression-bucket counts that are already computed for
   * the regular control flow.
   */
  onMetrics?: (metrics: DiagnosticsMetrics) => void
}

export async function diagnosticsAcrossRegistry(
  text: string,
  registry: AnalyzerRegistry,
  options: DiagnosticsAcrossRegistryOptions = {}
): Promise<DiagnosticDto[]> {
  // We always want to fire the metrics callback exactly once, even on
  // the empty-pending fast path, so the provider's per-refresh log
  // line is consistent across documents.
  const emitMetrics = (metrics: DiagnosticsMetrics): void => {
    if (options.onMetrics) options.onMetrics(metrics)
  }
  const emitSuppression = (event: SuppressionEvent): void => {
    if (options.onSuppression) options.onSuppression(event)
  }

  if (!text) {
    emitMetrics({ scanned: 0, droppedBySeverityOverride: 0, droppedByDisableComments: 0 })
    return []
  }
  const lineStarts = computeLineStarts(text)
  type Pending = { finding: Finding; analyzerId: string; range: DiagnosticRangeDto }
  const pending: Pending[] = []

  for (const analyzer of registry.list()) {
    for (const match of analyzer.detect(text)) {
      try {
        const result = await Promise.resolve(analyzer.analyze(match))
        const range = match.range
          ? rangeForOffsets(match.range.start, match.range.end, lineStarts, text)
          : rangeForLine(0, text.length)
        for (const finding of result.findings) {
          pending.push({ finding, analyzerId: analyzer.id, range })
        }
      } catch {
        // analyzer can't decode this match — skip
      }
    }
  }

  if (pending.length === 0) {
    emitMetrics({ scanned: 0, droppedBySeverityOverride: 0, droppedByDisableComments: 0 })
    return []
  }

  // 1. Apply per-rule severity overrides first so `off` drops findings
  //    even when no inline disable directive matches. We annotate each
  //    finding with its pending index so we can round-trip back to the
  //    source range / analyzer-id without re-running detect/analyze.
  const overrides = options.ruleSeverity ?? {}
  type TaggedFinding = Finding & { __idx: number }
  const taggedForOverrides: TaggedFinding[] = pending.map((p, idx) => ({
    ...p.finding,
    __idx: idx,
  }))
  const afterOverrides = applySeverityOverrides(
    taggedForOverrides,
    overrides
  ) as TaggedFinding[]

  // Emit one suppression event per finding the override pass dropped.
  // The set of surviving indices is small enough that the
  // O(pending) diff stays cheap; the alternative (rewriting the
  // override mapper to surface drop reasons) would leak provider-
  // facing concerns into a pure helper.
  const survivedOverrideIndices = new Set<number>()
  for (const tagged of afterOverrides) survivedOverrideIndices.add(tagged.__idx)
  let droppedBySeverityOverride = 0
  for (let i = 0; i < pending.length; i++) {
    if (survivedOverrideIndices.has(i)) continue
    droppedBySeverityOverride++
    emitSuppression({
      reason: 'severityOverride',
      findingId: pending[i].finding.id,
      analyzerId: pending[i].analyzerId,
      startLine: pending[i].range.startLine,
    })
  }

  if (afterOverrides.length === 0) {
    emitMetrics({
      scanned: pending.length,
      droppedBySeverityOverride,
      droppedByDisableComments: 0,
    })
    return []
  }

  // Rebuild the pending list with the (potentially) updated severity
  // values so downstream consumers (and the disable-comment filter's
  // tag round-trip) see the right shape.
  const overridden: Pending[] = afterOverrides.map((finding) => {
    const original = pending[finding.__idx]
    const { __idx: _ignored, ...cleanFinding } = finding
    return {
      finding: cleanFinding as Finding,
      analyzerId: original.analyzerId,
      range: original.range,
    }
  })

  // 2. Apply inline-disable-comments at the registry boundary so all
  //    downstream consumers (diagnostics, code lens, tree view, status
  //    bar) inherit the same suppression rules. Hover / inlay-hints /
  //    document-symbols / document-links re-run the same filter against
  //    each hit's findings before they map them to provider DTOs.
  //
  //    The filter is positional (rule id + line), so we annotate each
  //    pending finding with its index and ask the pure filter to
  //    preserve those tags — that lets us round-trip back to the
  //    original DTO without dropping duplicates that happen to share
  //    id + line.
  type TaggedWithLine = FindingWithLocation & { __idx: number }
  const located: TaggedWithLine[] = overridden.map((p, idx) => ({
    ...p.finding,
    startLine: p.range.startLine,
    __idx: idx,
  }))
  const kept = applyDisableComments(located, text) as TaggedWithLine[]
  const keepIndices = new Set<number>()
  for (const tagged of kept) keepIndices.add(tagged.__idx)

  let droppedByDisableComments = 0
  for (let i = 0; i < overridden.length; i++) {
    if (keepIndices.has(i)) continue
    droppedByDisableComments++
    emitSuppression({
      reason: 'inlineDisableComment',
      findingId: overridden[i].finding.id,
      analyzerId: overridden[i].analyzerId,
      startLine: overridden[i].range.startLine,
    })
  }

  emitMetrics({
    scanned: pending.length,
    droppedBySeverityOverride,
    droppedByDisableComments,
  })

  const out: DiagnosticDto[] = []
  for (let i = 0; i < overridden.length; i++) {
    if (!keepIndices.has(i)) continue
    const p = overridden[i]
    out.push(findingToDiagnostic(p.finding, p.analyzerId, p.range))
  }
  return out
}

function rangeForLine(line: number, length: number): DiagnosticRangeDto {
  return { startLine: line, startColumn: 0, endLine: line, endColumn: length }
}

function rangeForOffsets(
  start: number,
  end: number,
  lineStarts: number[],
  text: string
): DiagnosticRangeDto {
  const s = positionFor(start, lineStarts)
  const e = positionFor(Math.min(end, text.length), lineStarts)
  return { startLine: s.line, startColumn: s.column, endLine: e.line, endColumn: e.column }
}

function computeLineStarts(text: string): number[] {
  const starts = [0]
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1)
  }
  return starts
}

function positionFor(offset: number, lineStarts: number[]): { line: number; column: number } {
  let lo = 0
  let hi = lineStarts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (lineStarts[mid] <= offset) lo = mid
    else hi = mid - 1
  }
  return { line: lo, column: offset - lineStarts[lo] }
}
