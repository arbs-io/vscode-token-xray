import { describe, expect, it, vi } from 'vitest'
import { AnalyzerRegistry } from './registry'
import { ScanCache } from './scanCache'
import { AnalysisResult, Analyzer, Match } from './types'

/**
 * Minimal analyzer that emits one finding per occurrence of the exact
 * string `MARKER`. Configurable so individual tests can swap behaviour
 * without registering an entire shipped analyzer.
 */
function fakeAnalyzer(opts: {
  id?: string
  name?: string
  kind?: string
  detect?: (text: string) => Match[]
  analyze?: (match: Match) => AnalysisResult | Promise<AnalysisResult>
} = {}): Analyzer {
  const id = opts.id ?? 'fake'
  const name = opts.name ?? 'Fake'
  const kind = opts.kind ?? 'fake-kind'
  const detect = opts.detect ?? ((text) => {
    const out: Match[] = []
    const needle = 'MARKER'
    let i = 0
    while ((i = text.indexOf(needle, i)) !== -1) {
      out.push({ text: needle, range: { start: i, end: i + needle.length } })
      i += needle.length
    }
    return out
  })
  const analyze = opts.analyze ?? ((m): AnalysisResult => ({
    analyzerId: id,
    kind,
    sections: [{ id: 's1', title: 'Section', rows: [{ key: 'k', value: m.text }] }],
    findings: [{ id: 'fake.finding', severity: 'info', message: 'hit' }],
  }))
  return { id, name, detect, analyze }
}

function registryWith(...analyzers: Analyzer[]): AnalyzerRegistry {
  const reg = new AnalyzerRegistry()
  for (const a of analyzers) reg.register(a)
  return reg
}

describe('ScanCache — hit/miss', () => {
  it('returns identical results for the same (uri, version) key without re-running the analyzer', () => {
    const detectSpy = vi.fn((text: string) =>
      text.includes('MARKER') ? [{ text: 'MARKER', range: { start: 0, end: 6 } }] : []
    )
    const analyzeSpy = vi.fn((m: Match): AnalysisResult => ({
      analyzerId: 'fake',
      kind: 'k',
      sections: [],
      findings: [{ id: 'fake.hit', severity: 'info', message: m.text }],
    }))
    const reg = registryWith(fakeAnalyzer({ detect: detectSpy, analyze: analyzeSpy }))
    const cache = new ScanCache()

    const first = cache.getTokens({ uriKey: 'file:///x.ts', version: 1, text: 'MARKER', registry: reg })
    const second = cache.getTokens({ uriKey: 'file:///x.ts', version: 1, text: 'MARKER', registry: reg })

    expect(first).toBe(second)
    expect(first).toHaveLength(1)
    // detect is called twice — once during scanDocument's loop, once
    // during the analyzer-registry confirmAnalyzable path, but only
    // for the FIRST getTokens. The second call hits the cache.
    expect(detectSpy.mock.calls.length).toBeLessThanOrEqual(2)
    expect(analyzeSpy.mock.calls.length).toBeGreaterThanOrEqual(1)
    const callsAfterFirst = analyzeSpy.mock.calls.length
    cache.getTokens({ uriKey: 'file:///x.ts', version: 1, text: 'MARKER', registry: reg })
    expect(analyzeSpy.mock.calls.length).toBe(callsAfterFirst)
  })

  it('re-runs the analyzer when the version changes', () => {
    const analyzeSpy = vi.fn((m: Match): AnalysisResult => ({
      analyzerId: 'fake',
      kind: 'k',
      sections: [],
      findings: [{ id: 'fake.hit', severity: 'info', message: m.text }],
    }))
    const reg = registryWith(fakeAnalyzer({ analyze: analyzeSpy }))
    const cache = new ScanCache()

    cache.getTokens({ uriKey: 'file:///x.ts', version: 1, text: 'MARKER', registry: reg })
    const callsAtV1 = analyzeSpy.mock.calls.length
    cache.getTokens({ uriKey: 'file:///x.ts', version: 2, text: 'MARKER edited', registry: reg })
    expect(analyzeSpy.mock.calls.length).toBeGreaterThan(callsAtV1)
  })

  it('keeps only the latest version per URI', () => {
    const reg = registryWith(fakeAnalyzer())
    const cache = new ScanCache()

    cache.getTokens({ uriKey: 'file:///x.ts', version: 1, text: 'MARKER', registry: reg })
    cache.getTokens({ uriKey: 'file:///x.ts', version: 2, text: 'MARKER', registry: reg })
    cache.getTokens({ uriKey: 'file:///x.ts', version: 3, text: 'MARKER', registry: reg })
    expect(cache.size).toBe(1)
  })

  it('keys URIs independently', () => {
    const reg = registryWith(fakeAnalyzer())
    const cache = new ScanCache()
    cache.getTokens({ uriKey: 'file:///a.ts', version: 1, text: 'MARKER', registry: reg })
    cache.getTokens({ uriKey: 'file:///b.ts', version: 1, text: 'MARKER', registry: reg })
    expect(cache.size).toBe(2)
  })
})

describe('ScanCache — invalidation', () => {
  it('invalidate(uri) drops every version for that URI only', () => {
    const reg = registryWith(fakeAnalyzer())
    const cache = new ScanCache()
    cache.getTokens({ uriKey: 'file:///a.ts', version: 1, text: 'MARKER', registry: reg })
    cache.getTokens({ uriKey: 'file:///b.ts', version: 1, text: 'MARKER', registry: reg })

    cache.invalidate('file:///a.ts')
    expect(cache.size).toBe(1)
    // Subsequent get for the invalidated URI re-runs the analyzer.
    const analyzeSpy = vi.fn((): AnalysisResult => ({
      analyzerId: 'fake',
      kind: 'k',
      sections: [],
      findings: [],
    }))
    const reg2 = registryWith(fakeAnalyzer({ analyze: analyzeSpy }))
    cache.getTokens({ uriKey: 'file:///a.ts', version: 1, text: 'MARKER', registry: reg2 })
    expect(analyzeSpy).toHaveBeenCalled()
  })

  it('clear() drops everything', () => {
    const reg = registryWith(fakeAnalyzer())
    const cache = new ScanCache()
    cache.getTokens({ uriKey: 'file:///a.ts', version: 1, text: 'MARKER', registry: reg })
    cache.getTokens({ uriKey: 'file:///b.ts', version: 1, text: 'MARKER', registry: reg })
    cache.clear()
    expect(cache.size).toBe(0)
  })
})

describe('ScanCache — analyzer error policy', () => {
  it('skips analyzers whose analyze() returns a Promise', () => {
    const reg = registryWith(
      fakeAnalyzer({
        id: 'async',
        analyze: async () => ({
          analyzerId: 'async',
          kind: 'k',
          sections: [],
          findings: [],
        }),
      })
    )
    const cache = new ScanCache()
    const tokens = cache.getTokens({
      uriKey: 'file:///a.ts',
      version: 1,
      text: 'MARKER',
      registry: reg,
    })
    expect(tokens).toEqual([])
  })

  it('skips matches whose analyze() throws but keeps others', () => {
    const okAnalyzer = fakeAnalyzer({ id: 'ok' })
    let throwOnce = true
    const flaky = fakeAnalyzer({
      id: 'flaky',
      detect: (text) => (text.includes('FLAKY') ? [{ text: 'FLAKY', range: { start: 0, end: 5 } }] : []),
      analyze: () => {
        if (throwOnce) {
          throwOnce = false
          throw new Error('boom')
        }
        return { analyzerId: 'flaky', kind: 'k', sections: [], findings: [] }
      },
    })
    const reg = registryWith(okAnalyzer, flaky)
    const cache = new ScanCache()
    const tokens = cache.getTokens({
      uriKey: 'file:///a.ts',
      version: 1,
      text: 'FLAKY then MARKER',
      registry: reg,
    })
    // FLAKY is dropped at the `confirmAnalyzable` check in scanDocument
    // (since its analyze throws on the first call), so only the OK
    // analyzer's MARKER hit survives.
    expect(tokens).toHaveLength(1)
    expect(tokens[0].analyzerId).toBe('ok')
  })
})
