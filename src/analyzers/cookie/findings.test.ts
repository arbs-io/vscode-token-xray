import { describe, expect, it } from 'vitest'
import { evaluateCookie } from './findings'
import { parseSetCookie } from './parser'

const evalCookie = (header: string) => evaluateCookie(parseSetCookie(header))

describe('evaluateCookie', () => {
  it('flags SameSite=None without Secure as error', () => {
    const f = evalCookie('a=1; SameSite=None')
    expect(f.find((x) => x.id === 'cookie.sameSite.noneWithoutSecure')?.severity).toBe('error')
  })

  it('flags missing Secure on a sensitive cookie as warning', () => {
    const f = evalCookie('session=abc; HttpOnly; SameSite=Strict')
    expect(f.find((x) => x.id === 'cookie.secure.missing')?.severity).toBe('warning')
  })

  it('flags missing HttpOnly on a sensitive cookie as warning', () => {
    const f = evalCookie('jwt=abc; Secure; SameSite=Strict')
    expect(f.find((x) => x.id === 'cookie.httpOnly.missing')?.severity).toBe('warning')
  })

  it('flags missing SameSite on sensitive cookie as info', () => {
    const f = evalCookie('auth=abc; Secure; HttpOnly')
    expect(f.find((x) => x.id === 'cookie.sameSite.missing')?.severity).toBe('info')
  })

  it('flags session cookie (no Expires / Max-Age) as info', () => {
    const f = evalCookie('a=1; Secure')
    expect(f.find((x) => x.id === 'cookie.expiry.missing')?.severity).toBe('info')
  })

  it('flags cookie value that is a JWT', () => {
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig'
    const f = evalCookie(`token=${jwt}; Secure; HttpOnly`)
    expect(f.find((x) => x.id === 'cookie.value.jwt')).toBeDefined()
  })

  it('flags overly broad Domain (public suffix)', () => {
    const f = evalCookie('a=1; Domain=.com; Secure')
    expect(f.find((x) => x.id === 'cookie.domain.tooBroad')?.severity).toBe('warning')
  })

  it('flags negative Max-Age as a deletion', () => {
    const f = evalCookie('a=1; Max-Age=-1; Secure')
    expect(f.find((x) => x.id === 'cookie.maxAge.deletion')?.severity).toBe('info')
  })

  it('produces no errors for a well-configured session cookie', () => {
    const f = evalCookie('session=abc; Secure; HttpOnly; SameSite=Strict; Max-Age=3600')
    expect(f.find((x) => x.severity === 'error')).toBeUndefined()
  })

  it('does not warn HttpOnly/Secure for non-sensitive cookies', () => {
    const f = evalCookie('locale=en-US; Path=/; Max-Age=86400')
    expect(f.find((x) => x.id === 'cookie.httpOnly.missing')).toBeUndefined()
    expect(f.find((x) => x.id === 'cookie.secure.missing')).toBeUndefined()
  })
})
