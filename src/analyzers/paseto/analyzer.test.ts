import { describe, expect, it } from 'vitest'
import { PasetoAnalyzer } from './analyzer'

const SIG_BYTES = { v1: 256, v2: 64, v3: 96, v4: 64 } as const

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function fakePublic(version: 'v1' | 'v2' | 'v3' | 'v4', claims: object): string {
  const json = new TextEncoder().encode(JSON.stringify(claims))
  const sig = new Uint8Array(SIG_BYTES[version])
  const combined = new Uint8Array(json.length + sig.length)
  combined.set(json, 0)
  combined.set(sig, json.length)
  return `${version}.public.${b64u(combined)}`
}

function fakeLocal(version: 'v1' | 'v2' | 'v3' | 'v4'): string {
  return `${version}.local.${b64u(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))}`
}

describe('PasetoAnalyzer.detect', () => {
  const analyzer = new PasetoAnalyzer()

  it('returns no matches for empty / non-PASETO input', () => {
    expect(analyzer.detect('')).toEqual([])
    expect(analyzer.detect('hello world')).toEqual([])
  })

  it('finds a single token in surrounding text', () => {
    const token = fakePublic('v4', { sub: 'alice' })
    const matches = analyzer.detect(`PASETO=${token} (logged at boot)`)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toBe(token)
  })

  it('finds multiple tokens in mixed text', () => {
    const a = fakePublic('v4', { sub: 'a' })
    const b = fakeLocal('v2')
    const matches = analyzer.detect(`first ${a}\nsecond ${b}\nend`)
    expect(matches.map((m) => m.text)).toEqual([a, b])
  })

  it('skips strings whose payload section cannot be decoded', () => {
    // payload contains characters outside [A-Za-z0-9_-] so the regex itself
    // refuses to extend that far — should yield no matches.
    expect(analyzer.detect('v4.public.@@@@')).toEqual([])
  })

  it('does not match unknown versions', () => {
    expect(analyzer.detect('v5.public.abcdef')).toEqual([])
  })

  it('provides byte ranges covering the token', () => {
    const token = fakePublic('v4', { sub: 'a' })
    const prefix = 'BEFORE '
    const matches = analyzer.detect(`${prefix}${token} AFTER`)
    expect(matches[0].range).toEqual({ start: prefix.length, end: prefix.length + token.length })
  })
})

describe('PasetoAnalyzer.analyze', () => {
  const analyzer = new PasetoAnalyzer()

  it('produces a header section listing version + purpose', () => {
    const token = fakePublic('v4', { sub: 'alice' })
    const result = analyzer.analyze({ text: token })
    expect(result.analyzerId).toBe('paseto')
    expect(result.kind).toBe('PASETO v4.public')
    expect(result.sections[0].id).toBe('header')
    const rows = result.sections[0].rows
    expect(rows.find((r) => r.key === 'version')?.value).toBe('v4')
    expect(rows.find((r) => r.key === 'purpose')?.value).toBe('public')
  })

  it('renders public claims in a Claims section', () => {
    const token = fakePublic('v4', { sub: 'alice', iat: 1700000000 })
    const result = analyzer.analyze({ text: token })
    const claims = result.sections.find((s) => s.id === 'payload')
    expect(claims?.title).toBe('Claims')
    expect(claims?.rows.find((r) => r.key === 'sub')?.value).toBe('alice')
    expect(claims?.rows.find((r) => r.key === 'iat')?.value).toBe(1700000000)
  })

  it('marks local payload as encrypted', () => {
    const token = fakeLocal('v4')
    const result = analyzer.analyze({ text: token })
    const payload = result.sections.find((s) => s.id === 'payload')
    expect(payload?.rows[0].description).toMatch(/encrypted/i)
    expect(result.findings.find((f) => f.id === 'paseto.purpose.local')).toBeDefined()
  })

  it('surfaces deprecation finding for v2', () => {
    const token = fakePublic('v2', { sub: 'x' })
    const result = analyzer.analyze({ text: token })
    expect(result.findings.find((f) => f.id === 'paseto.version.deprecated')).toBeDefined()
  })

  it('exposes the footer when present', () => {
    const footer = Buffer.from('{"kid":"k1"}').toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
    const token = `${fakePublic('v4', { sub: 'x' })}.${footer}`
    const result = analyzer.analyze({ text: token })
    const headerRows = result.sections[0].rows
    expect(headerRows.find((r) => r.key === 'footer')?.value).toBe('{"kid":"k1"}')
  })

  it('renders an "invalid payload" section when public payload cannot be decoded', () => {
    const tiny = Buffer.from(new Uint8Array([1, 2, 3, 4])).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
    const result = analyzer.analyze({ text: `v4.public.${tiny}` })
    const payload = result.sections.find((s) => s.id === 'payload')
    expect(payload?.rows[0].value).toBe('invalid')
    expect(result.findings.find((f) => f.id === 'paseto.payload.invalid')).toBeDefined()
  })

  it('throws when given a string that is not a PASETO shape', () => {
    expect(() => analyzer.analyze({ text: 'not a paseto' })).toThrow(/PASETO/i)
  })
})
