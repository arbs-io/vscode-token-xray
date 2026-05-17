import { describe, expect, it } from 'vitest'
import { createDefaultRegistry } from './defaultRegistry'
import { scanDocument } from './scanDocument'
import { samlResponseFixture } from '../analyzers/saml/fixtures'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
}

const JWT = `${b64u({ alg: 'RS256' })}.${b64u({ sub: 'a' })}.sig`

describe('scanDocument', () => {
  const reg = createDefaultRegistry()

  it('finds JWTs without any language id', () => {
    const text = `// some js\nconst token = "${JWT}"\n`
    const hits = scanDocument(text, reg)
    expect(hits).toHaveLength(1)
    expect(hits[0].analyzerId).toBe('jwt')
    expect(hits[0].startLine).toBe(1)
  })

  it('finds SAML responses (raw XML)', () => {
    const text = samlResponseFixture({ signed: true })
    const hits = scanDocument(text, reg)
    expect(hits.some((h) => h.analyzerId === 'saml')).toBe(true)
  })

  it('finds both kinds in the same document', () => {
    const text = `JWT: ${JWT}\n\n${samlResponseFixture({ signed: true })}`
    const hits = scanDocument(text, reg)
    const ids = new Set(hits.map((h) => h.analyzerId))
    expect(ids.has('jwt')).toBe(true)
    expect(ids.has('saml')).toBe(true)
  })

  it('returns nothing for plain text', () => {
    expect(scanDocument('just some words', reg)).toEqual([])
  })

  it('returns nothing for empty input', () => {
    expect(scanDocument('', reg)).toEqual([])
  })

  it('skips documents over maxBytes', () => {
    const big = JWT + 'x'.repeat(2000)
    expect(scanDocument(big, reg, { maxBytes: 100 })).toEqual([])
  })

  it('dedupes overlapping matches (longer wins)', () => {
    const text = JWT
    const hits = scanDocument(text, reg)
    expect(hits).toHaveLength(1)
  })

  it('drops detections where analyze throws', () => {
    const registryWithBad = createDefaultRegistry()
    registryWithBad.register({
      id: 'bogus',
      name: 'bogus',
      detect: (text: string) =>
        text.length > 0 ? [{ text, range: { start: 0, end: text.length } }] : [],
      analyze: () => {
        throw new Error('cannot analyze')
      },
    })
    const hits = scanDocument('hello world', registryWithBad)
    expect(hits.every((h) => h.analyzerId !== 'bogus')).toBe(true)
  })
})
