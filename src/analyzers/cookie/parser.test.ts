import { describe, expect, it } from 'vitest'
import { extractSetCookieHeaders, parseSetCookie } from './parser'

describe('extractSetCookieHeaders', () => {
  it('finds Set-Cookie lines (case-insensitive)', () => {
    const text = 'HTTP/1.1 200 OK\nset-cookie: a=1\nSet-Cookie: b=2; HttpOnly\n'
    const hits = extractSetCookieHeaders(text)
    expect(hits).toHaveLength(2)
    expect(hits[0].value).toBe('a=1')
    expect(hits[1].value).toBe('b=2; HttpOnly')
  })

  it('returns empty for input without Set-Cookie', () => {
    expect(extractSetCookieHeaders('Cookie: a=1')).toEqual([])
    expect(extractSetCookieHeaders('')).toEqual([])
  })

  it('captures byte offsets', () => {
    const text = 'prefix\nSet-Cookie: x=y'
    const [hit] = extractSetCookieHeaders(text)
    expect(hit.start).toBe(text.indexOf('Set-Cookie'))
  })
})

describe('parseSetCookie', () => {
  it('parses name=value', () => {
    const c = parseSetCookie('session=abc123')
    expect(c.name).toBe('session')
    expect(c.value).toBe('abc123')
    expect(c.attributes.secure).toBe(false)
    expect(c.attributes.httpOnly).toBe(false)
  })

  it('strips quotes around the value', () => {
    expect(parseSetCookie('x="hello world"').value).toBe('hello world')
  })

  it('parses Secure, HttpOnly, Partitioned flags', () => {
    const c = parseSetCookie('a=1; Secure; HttpOnly; Partitioned')
    expect(c.attributes.secure).toBe(true)
    expect(c.attributes.httpOnly).toBe(true)
    expect(c.attributes.partitioned).toBe(true)
  })

  it('parses Domain (strips leading dot)', () => {
    expect(parseSetCookie('a=1; Domain=.example.com').attributes.domain).toBe('example.com')
  })

  it('parses Path, Expires, Max-Age, SameSite', () => {
    const c = parseSetCookie('a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=3600; SameSite=Strict')
    expect(c.attributes.path).toBe('/')
    expect(c.attributes.expires).toContain('Wed, 21 Oct 2026')
    expect(c.attributes.maxAge).toBe(3600)
    expect(c.attributes.sameSite).toBe('Strict')
  })

  it('normalises SameSite case', () => {
    expect(parseSetCookie('a=1; samesite=lax').attributes.sameSite).toBe('Lax')
    expect(parseSetCookie('a=1; SameSite=none').attributes.sameSite).toBe('None')
  })

  it('ignores unknown attributes', () => {
    const c = parseSetCookie('a=1; Foo=bar; Secure')
    expect(c.attributes.secure).toBe(true)
  })

  it('throws on empty input', () => {
    expect(() => parseSetCookie('')).toThrow()
    expect(() => parseSetCookie('  ')).toThrow()
  })

  it('throws when missing name=value', () => {
    expect(() => parseSetCookie('; Secure')).toThrow(/missing name=value/)
  })

  it('throws when name is empty', () => {
    expect(() => parseSetCookie('=value')).toThrow(/missing cookie name/)
  })

  it('preserves empty values', () => {
    expect(parseSetCookie('a=').value).toBe('')
  })

  it('ignores non-numeric Max-Age', () => {
    expect(parseSetCookie('a=1; Max-Age=forever').attributes.maxAge).toBeUndefined()
  })
})
