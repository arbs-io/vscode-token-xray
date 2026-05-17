import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { JwkAnalyzer } from './analyzer'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

describe('JwkAnalyzer', () => {
  const analyzer = new JwkAnalyzer()

  it('detects a single JWK document', () => {
    const matches = analyzer.detect(read('rsa-public.json'))
    expect(matches).toHaveLength(1)
  })

  it('detects a JWKS document', () => {
    expect(analyzer.detect(read('jwks.json'))).toHaveLength(1)
  })

  it('does not match arbitrary JSON', () => {
    expect(analyzer.detect('{"foo": 1}')).toEqual([])
  })

  it('does not match non-JSON', () => {
    expect(analyzer.detect('plain text')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces one section per key in a JWKS', () => {
    const [m] = analyzer.detect(read('jwks.json'))
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('JWKS')
    expect(result.sections).toHaveLength(2)
    expect(result.sections[0].id).toBe('key-0')
    expect(result.sections[1].id).toBe('key-1')
  })

  it('produces one section for a single JWK', () => {
    const [m] = analyzer.detect(read('rsa-public.json'))
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('JWK')
    expect(result.sections).toHaveLength(1)
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('kty')
    expect(keys).toContain('keySizeBits')
  })

  it('surfaces error findings for private material', () => {
    const [m] = analyzer.detect(read('ec-private.json'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id.endsWith('private.present'))?.severity).toBe('error')
  })
})
