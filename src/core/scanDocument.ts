import { Analyzer, Match } from './types'
import { AnalyzerRegistry } from './registry'

export interface DetectedToken {
  analyzerId: string
  analyzerName: string
  text: string
  startOffset: number
  endOffset: number
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
}

export interface ScanOptions {
  maxBytes?: number
}

export function scanDocument(
  text: string,
  registry: AnalyzerRegistry,
  options: ScanOptions = {}
): DetectedToken[] {
  const max = options.maxBytes ?? 1_000_000
  if (text.length === 0 || text.length > max) return []
  const lineStarts = computeLineStarts(text)
  const found: DetectedToken[] = []

  for (const analyzer of registry.list()) {
    for (const match of analyzer.detect(text)) {
      const range = match.range
      if (!range) continue
      if (!confirmAnalyzable(analyzer, match)) continue
      const start = positionFor(range.start, lineStarts)
      const end = positionFor(range.end, lineStarts)
      found.push({
        analyzerId: analyzer.id,
        analyzerName: analyzer.name,
        text: match.text,
        startOffset: range.start,
        endOffset: range.end,
        startLine: start.line,
        startColumn: start.column,
        endLine: end.line,
        endColumn: end.column,
      })
    }
  }

  return dedupe(found)
}

function confirmAnalyzable(analyzer: Analyzer, match: Match): boolean {
  try {
    analyzer.analyze(match)
    return true
  } catch {
    return false
  }
}

function dedupe(hits: DetectedToken[]): DetectedToken[] {
  // Prefer the longer match if two analyzers overlap on the same range.
  hits.sort((a, b) => a.startOffset - b.startOffset || b.endOffset - a.endOffset)
  const out: DetectedToken[] = []
  for (const hit of hits) {
    const last = out[out.length - 1]
    if (last && hit.startOffset < last.endOffset) continue
    out.push(hit)
  }
  return out
}

function computeLineStarts(text: string): number[] {
  const starts = [0]
  for (let i = 0; i < text.length; i++) {
    if (text.codePointAt(i) === 10) starts.push(i + 1)
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
