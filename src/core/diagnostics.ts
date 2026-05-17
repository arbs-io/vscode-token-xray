import { Finding, Severity } from './types'
import { AnalyzerRegistry } from './registry'
import { applyDisableComments, FindingWithLocation } from './disableComments'

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

export async function diagnosticsAcrossRegistry(
  text: string,
  registry: AnalyzerRegistry
): Promise<DiagnosticDto[]> {
  if (!text) return []
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

  if (pending.length === 0) return []

  // Apply inline-disable-comments at the registry boundary so all
  // downstream consumers (diagnostics, code lens, tree view, status
  // bar) inherit the same suppression rules. Hover / inlay-hints /
  // document-symbols / document-links re-run the same filter against
  // each hit's findings before they map them to provider DTOs.
  //
  // The filter is positional (rule id + line), so we annotate each
  // pending finding with its index and ask the pure filter to preserve
  // those tags — that lets us round-trip back to the original DTO
  // without dropping duplicates that happen to share id + line.
  type TaggedFinding = FindingWithLocation & { __idx: number }
  const located: TaggedFinding[] = pending.map((p, idx) => ({
    ...p.finding,
    startLine: p.range.startLine,
    __idx: idx,
  }))
  const kept = applyDisableComments(located, text) as TaggedFinding[]
  const keepIndices = new Set<number>()
  for (const tagged of kept) keepIndices.add(tagged.__idx)

  const out: DiagnosticDto[] = []
  for (let i = 0; i < pending.length; i++) {
    if (!keepIndices.has(i)) continue
    const p = pending[i]
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
