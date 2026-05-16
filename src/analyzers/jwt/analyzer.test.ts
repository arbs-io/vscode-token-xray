import { describe, expect, it } from 'vitest'
import { JwtAnalyzer } from './analyzer'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

const NOW = Date.UTC(2026, 0, 1)
const VALID = `${b64u({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${b64u({ sub: 'alice', iss: 'me', aud: 'you', exp: Math.floor(NOW / 1000) + 3600 })}.sig`

describe('JwtAnalyzer', () => {
  const analyzer = new JwtAnalyzer({ now: NOW })

  it('detects JWTs embedded in text', () => {
    const text = `Authorization: Bearer ${VALID}\nsome other content`
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toBe(VALID)
    expect(matches[0].range?.start).toBe(text.indexOf(VALID))
  })

  it('detects multiple JWTs in one document', () => {
    const text = `${VALID}\n\n${VALID}`
    expect(analyzer.detect(text)).toHaveLength(2)
  })

  it('does not falsely match arbitrary text', () => {
    expect(analyzer.detect('hello world')).toEqual([])
  })

  it('returns an empty detection list for empty input', () => {
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces a header section, claims section, and findings', () => {
    const [match] = analyzer.detect(VALID)
    const result = analyzer.analyze(match)
    expect(result.analyzerId).toBe('jwt')
    expect(result.kind).toBe('JWS')
    expect(result.sections.map((s) => s.id)).toEqual(['header', 'payload'])
    expect(result.findings).toEqual([])
  })

  it('produces only a header section for a JWE', () => {
    const jwe = `${b64u({ alg: 'RSA-OAEP', enc: 'A256GCM' })}.encKey.iv.ct.tag`
    const [match] = analyzer.detect(jwe)
    const result = analyzer.analyze(match)
    expect(result.kind).toBe('JWE')
    expect(result.sections.map((s) => s.id)).toEqual(['header'])
  })

  it('renders timestamp claims with ISO suffix', () => {
    const [match] = analyzer.detect(VALID)
    const result = analyzer.analyze(match)
    const claims = result.sections.find((s) => s.id === 'payload')!
    const exp = claims.rows.find((r) => r.key === 'exp')!
    expect(typeof exp.value).toBe('string')
    expect(exp.value).toMatch(/T.*Z\)$/)
  })

  it('surfaces alg:none as an error finding', () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const [match] = analyzer.detect(token)
    const result = analyzer.analyze(match)
    expect(result.findings.find((f) => f.id === 'jwt.alg.none')?.severity).toBe('error')
  })
})
