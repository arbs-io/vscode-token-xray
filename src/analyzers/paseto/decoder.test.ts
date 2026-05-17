import { describe, expect, it } from 'vitest'
import { decodePaseto, looksLikePaseto } from './decoder'

/** Same byte counts as decoder.ts SIG_BYTES — kept here so test fixtures are self-contained. */
const SIG_BYTES = { v1: 256, v2: 64, v3: 96, v4: 64 } as const

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function b64uStr(s: string): string {
  return b64u(new TextEncoder().encode(s))
}

/** Build a synthetic PASETO `vN.public.{payload}` token whose payload is
 *  `JSON.stringify(claims)` followed by `sigLen` zero bytes (so the decoder
 *  can strip them and JSON-parse the claims). */
function fakePublic(version: 'v1' | 'v2' | 'v3' | 'v4', claims: object, footer?: string): string {
  const json = new TextEncoder().encode(JSON.stringify(claims))
  const sig = new Uint8Array(SIG_BYTES[version])
  const combined = new Uint8Array(json.length + sig.length)
  combined.set(json, 0)
  combined.set(sig, json.length)
  const base = `${version}.public.${b64u(combined)}`
  return footer === undefined ? base : `${base}.${b64uStr(footer)}`
}

function fakeLocal(version: 'v1' | 'v2' | 'v3' | 'v4', footer?: string): string {
  // local payload is just opaque bytes — use a fixed blob
  const blob = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  const base = `${version}.local.${b64u(blob)}`
  return footer === undefined ? base : `${base}.${b64uStr(footer)}`
}

describe('looksLikePaseto', () => {
  it('accepts v1–v4 local and public shapes', () => {
    for (const v of ['v1', 'v2', 'v3', 'v4'] as const) {
      expect(looksLikePaseto(`${v}.local.abc`)).toBe(true)
      expect(looksLikePaseto(`${v}.public.abc`)).toBe(true)
    }
  })

  it('accepts an optional footer segment', () => {
    expect(looksLikePaseto('v4.public.abc.def')).toBe(true)
  })

  it('rejects unknown versions and purposes', () => {
    expect(looksLikePaseto('v5.public.abc')).toBe(false)
    expect(looksLikePaseto('v0.public.abc')).toBe(false)
    expect(looksLikePaseto('v4.secret.abc')).toBe(false)
  })

  it('rejects malformed strings', () => {
    expect(looksLikePaseto('v4.public')).toBe(false)
    expect(looksLikePaseto('not-a-token')).toBe(false)
    expect(looksLikePaseto('v4.public.bad chars!')).toBe(false)
  })
})

describe('decodePaseto', () => {
  it('returns undefined for empty / non-string input', () => {
    expect(decodePaseto('')).toBeUndefined()
    expect(decodePaseto(undefined as unknown as string)).toBeUndefined()
    expect(decodePaseto(null as unknown as string)).toBeUndefined()
  })

  it('returns undefined for malformed tokens', () => {
    expect(decodePaseto('v4.public')).toBeUndefined()
    expect(decodePaseto('garbage')).toBeUndefined()
    expect(decodePaseto('v9.public.abc')).toBeUndefined()
  })

  it('trims surrounding whitespace before parsing', () => {
    const token = `   ${fakeLocal('v4')}   `
    const decoded = decodePaseto(token)
    expect(decoded?.version).toBe('v4')
  })

  it.each(['v1', 'v2', 'v3', 'v4'] as const)(
    'decodes a %s.public token and recovers JSON claims',
    (version) => {
      const token = fakePublic(version, { sub: 'alice', iat: 1700000000 })
      const decoded = decodePaseto(token)
      expect(decoded).toBeDefined()
      if (!decoded) throw new Error('expected decoded')
      expect(decoded.version).toBe(version)
      expect(decoded.purpose).toBe('public')
      expect(decoded.payloadInvalid).toBe(false)
      expect(decoded.claims).toEqual({ sub: 'alice', iat: 1700000000 })
    }
  )

  it.each(['v1', 'v2', 'v3', 'v4'] as const)(
    'decodes a %s.local token but does not attempt to recover claims',
    (version) => {
      const token = fakeLocal(version)
      const decoded = decodePaseto(token)
      expect(decoded).toBeDefined()
      if (!decoded) throw new Error('expected decoded')
      expect(decoded.version).toBe(version)
      expect(decoded.purpose).toBe('local')
      expect(decoded.claims).toBeUndefined()
      expect(decoded.payloadInvalid).toBe(false)
    }
  )

  it('decodes a footer segment when it is printable text', () => {
    const token = fakePublic('v4', { sub: 'x' }, '{"kid":"k1"}')
    const decoded = decodePaseto(token)
    expect(decoded?.footerDecoded).toBe('{"kid":"k1"}')
  })

  it('leaves footerDecoded undefined when the footer holds non-printable bytes', () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc])
    const token = `v4.public.${b64u(new Uint8Array(SIG_BYTES.v4 + 2))}.${b64u(bytes)}`
    const decoded = decodePaseto(token)
    expect(decoded?.footer).toBeDefined()
    expect(decoded?.footerDecoded).toBeUndefined()
  })

  it('marks payload invalid when public payload is too short for a signature', () => {
    // Only 4 bytes — well below the 64-byte v4 signature length.
    const tiny = b64u(new Uint8Array([1, 2, 3, 4]))
    const decoded = decodePaseto(`v4.public.${tiny}`)
    expect(decoded?.payloadInvalid).toBe(true)
    expect(decoded?.claims).toBeUndefined()
  })

  it('marks payload invalid when claims segment is not JSON', () => {
    const junk = new TextEncoder().encode('this is not json at all!')
    const sig = new Uint8Array(SIG_BYTES.v4)
    const combined = new Uint8Array(junk.length + sig.length)
    combined.set(junk, 0)
    combined.set(sig, junk.length)
    const decoded = decodePaseto(`v4.public.${b64u(combined)}`)
    expect(decoded?.payloadInvalid).toBe(true)
  })

  it('marks payload invalid when claims segment decodes to a non-object JSON', () => {
    const arr = new TextEncoder().encode('[1,2,3]')
    const sig = new Uint8Array(SIG_BYTES.v4)
    const combined = new Uint8Array(arr.length + sig.length)
    combined.set(arr, 0)
    combined.set(sig, arr.length)
    const decoded = decodePaseto(`v4.public.${b64u(combined)}`)
    expect(decoded?.payloadInvalid).toBe(true)
  })

  it('marks payload invalid when claims segment is not valid UTF-8', () => {
    // 0xC3 0x28 is an invalid UTF-8 byte sequence.
    const bad = new Uint8Array([0xc3, 0x28, 0xc3, 0x28])
    const sig = new Uint8Array(SIG_BYTES.v4)
    const combined = new Uint8Array(bad.length + sig.length)
    combined.set(bad, 0)
    combined.set(sig, bad.length)
    const decoded = decodePaseto(`v4.public.${b64u(combined)}`)
    expect(decoded?.payloadInvalid).toBe(true)
  })

  it('preserves the original raw token', () => {
    const token = fakePublic('v3', { sub: 'a' })
    expect(decodePaseto(token)?.raw).toBe(token)
  })

  it('exposes the footer in raw form for non-printable footers', () => {
    const bytes = new Uint8Array([0xff, 0xfe])
    const token = `v4.public.${b64u(new Uint8Array(SIG_BYTES.v4 + 2))}.${b64u(bytes)}`
    const decoded = decodePaseto(token)
    expect(decoded?.footer).toBeDefined()
  })
})
