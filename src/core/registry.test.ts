import { describe, expect, it } from 'vitest'
import { AnalyzerRegistry } from './registry'
import { Analyzer, Match } from './types'

function fakeAnalyzer(id: string, pattern: RegExp): Analyzer {
  return {
    id,
    name: id,
    detect(text: string): Match[] {
      const m = pattern.exec(text)
      return m ? [{ text: m[0] }] : []
    },
    analyze() {
      return { analyzerId: id, kind: 'fake', sections: [], findings: [] }
    },
  }
}

describe('AnalyzerRegistry', () => {
  it('registers and retrieves analyzers by id', () => {
    const r = new AnalyzerRegistry()
    const a = fakeAnalyzer('a', /a/)
    r.register(a)
    expect(r.get('a')).toBe(a)
    expect(r.list()).toEqual([a])
  })

  it('rejects duplicate registration', () => {
    const r = new AnalyzerRegistry()
    r.register(fakeAnalyzer('a', /a/))
    expect(() => r.register(fakeAnalyzer('a', /b/))).toThrow(/already registered/)
  })

  it('detectAll aggregates matches across analyzers', () => {
    const r = new AnalyzerRegistry()
    r.register(fakeAnalyzer('a', /a/))
    r.register(fakeAnalyzer('b', /b/))
    const matches = r.detectAll('a b')
    expect(matches.map((m) => m.analyzer.id).sort((a, b) => a.localeCompare(b))).toEqual(['a', 'b'])
  })

  it('returns undefined for unknown analyzer ids', () => {
    const r = new AnalyzerRegistry()
    expect(r.get('missing')).toBeUndefined()
  })
})
