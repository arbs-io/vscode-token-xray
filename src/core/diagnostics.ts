import { Finding, Severity } from './types'
import { AnalyzerRegistry } from './registry'

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
  const out: DiagnosticDto[] = []

  for (const analyzer of registry.list()) {
    for (const match of analyzer.detect(text)) {
      try {
        const result = await Promise.resolve(analyzer.analyze(match))
        const range = match.range
          ? rangeForOffsets(match.range.start, match.range.end, lineStarts, text)
          : rangeForLine(0, text.length)
        for (const finding of result.findings) {
          out.push(findingToDiagnostic(finding, analyzer.id, range))
        }
      } catch {
        // analyzer can't decode this match — skip
      }
    }
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
