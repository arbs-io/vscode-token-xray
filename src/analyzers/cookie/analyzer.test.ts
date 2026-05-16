import { describe, expect, it } from 'vitest'
import { CookieAnalyzer } from './analyzer'

describe('CookieAnalyzer', () => {
  const analyzer = new CookieAnalyzer()

  it('detects Set-Cookie lines in a response capture', () => {
    const response = 'HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: session=abc; HttpOnly\n\n<html>'
    const matches = analyzer.detect(response)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toContain('session=abc')
  })

  it('detects multiple Set-Cookie headers', () => {
    const r = 'Set-Cookie: a=1\nSet-Cookie: b=2; Secure\n'
    expect(analyzer.detect(r)).toHaveLength(2)
  })

  it('returns no matches for plain text or empty', () => {
    expect(analyzer.detect('hello world')).toEqual([])
    expect(analyzer.detect('')).toEqual([])
  })

  it('produces section + findings on analyze', () => {
    const r = 'Set-Cookie: session=abc; SameSite=None'
    const [match] = analyzer.detect(r)
    const result = analyzer.analyze(match)
    expect(result.analyzerId).toBe('cookie')
    expect(result.sections[0].id).toBe('cookie')
    const keys = result.sections[0].rows.map((row) => row.key)
    expect(keys).toEqual(expect.arrayContaining(['name', 'value', 'sameSite', 'secure', 'httpOnly']))
    expect(result.findings.find((f) => f.id === 'cookie.sameSite.noneWithoutSecure')?.severity).toBe('error')
  })

  it('previews long values', () => {
    const long = 'x'.repeat(200)
    const [match] = analyzer.detect(`Set-Cookie: big=${long}`)
    const result = analyzer.analyze(match)
    const valueRow = result.sections[0].rows.find((r) => r.key === 'value')
    expect(typeof valueRow?.value).toBe('string')
    expect((valueRow?.value as string).length).toBeLessThan(long.length)
  })
})
