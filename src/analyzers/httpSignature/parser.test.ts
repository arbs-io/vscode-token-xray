import { describe, expect, it } from 'vitest'
import { parseCavageSignature, parseRfc9421 } from './parser'

describe('parseCavageSignature — positive cases', () => {
  it('parses the canonical example with algorithm + headers + signature', () => {
    const header =
      'Signature: keyId="alice",algorithm="rsa-sha256",headers="(request-target) host date",signature="base64=="'
    const result = parseCavageSignature(header)
    expect(result).toEqual({
      keyId: 'alice',
      algorithm: 'rsa-sha256',
      headers: ['(request-target)', 'host', 'date'],
      signature: 'base64==',
    })
  })

  it('parses the bare value (no `Signature:` prefix)', () => {
    const value = 'keyId="alice",algorithm="rsa-sha256",signature="b64=="'
    const result = parseCavageSignature(value)
    expect(result?.keyId).toBe('alice')
    expect(result?.algorithm).toBe('rsa-sha256')
  })

  it('parses a header without an algorithm parameter (algorithm derived from key)', () => {
    const header = 'Signature: keyId="bob",headers="(request-target) host",signature="QmFzZTY0=="'
    const result = parseCavageSignature(header)
    expect(result?.keyId).toBe('bob')
    expect(result?.algorithm).toBeUndefined()
    expect(result?.headers).toEqual(['(request-target)', 'host'])
  })

  it('parses created / expires as numeric values', () => {
    const header =
      'Signature: keyId="alice",created=1402170695,expires=1402170995,signature="b64=="'
    const result = parseCavageSignature(header)
    expect(result?.created).toBe(1402170695)
    expect(result?.expires).toBe(1402170995)
  })

  it('preserves commas inside quoted values (does not split on them)', () => {
    // The `keyId` value contains a comma; the splitter must not break
    // on it. (Cavage allows any printable ascii inside the quoted
    // value.)
    const header = 'Signature: keyId="alice,with,commas",signature="b64=="'
    const result = parseCavageSignature(header)
    expect(result?.keyId).toBe('alice,with,commas')
  })

  it('is case-insensitive on the header prefix', () => {
    expect(parseCavageSignature('signature: keyId="x",signature="y"')?.keyId).toBe('x')
    expect(parseCavageSignature('SIGNATURE: keyId="x",signature="y"')?.keyId).toBe('x')
  })

  it('tolerates whitespace around commas and equals signs', () => {
    const header =
      'Signature: keyId = "alice" , algorithm = "hmac-sha256" , signature = "b64=="'
    const result = parseCavageSignature(header)
    expect(result?.keyId).toBe('alice')
    expect(result?.algorithm).toBe('hmac-sha256')
  })

  it('handles a trailing comma without producing a malformed entry', () => {
    const header = 'Signature: keyId="alice",signature="b64==",'
    const result = parseCavageSignature(header)
    expect(result?.keyId).toBe('alice')
  })

  it('drops empty headers entries from the list', () => {
    const header = 'Signature: keyId="alice",headers="",signature="b64=="'
    const result = parseCavageSignature(header)
    expect(result?.keyId).toBe('alice')
    // Empty `headers=""` → headers field omitted from the result.
    expect(result?.headers).toBeUndefined()
  })

  it('accepts `=` form (`Signature= keyId="x",…`) used in some debug logs', () => {
    const header = 'Signature= keyId="x",signature="b64=="'
    expect(parseCavageSignature(header)?.keyId).toBe('x')
  })
})

describe('parseCavageSignature — negative cases', () => {
  it('returns undefined for non-string input', () => {
    expect(parseCavageSignature(undefined as unknown as string)).toBeUndefined()
    expect(parseCavageSignature(null as unknown as string)).toBeUndefined()
    expect(parseCavageSignature(42 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for empty / whitespace input', () => {
    expect(parseCavageSignature('')).toBeUndefined()
    expect(parseCavageSignature('   ')).toBeUndefined()
    expect(parseCavageSignature('Signature: ')).toBeUndefined()
  })

  it('returns undefined when the RFC 9421 inner-list form is detected', () => {
    // `sig1=("…")` → must be parsed by parseRfc9421, not the cavage
    // parser.
    expect(parseCavageSignature('Signature: sig1=("@method")')).toBeUndefined()
  })

  it('returns undefined when the RFC 9421 `<label>=:base64:` form is detected', () => {
    expect(parseCavageSignature('Signature: sig1=:base64==:')).toBeUndefined()
  })

  it('returns undefined when keyId is missing', () => {
    expect(parseCavageSignature('Signature: signature="b64=="')).toBeUndefined()
  })

  it('returns undefined when signature is missing', () => {
    expect(parseCavageSignature('Signature: keyId="alice"')).toBeUndefined()
  })

  it('returns undefined when keyId is an empty string', () => {
    expect(parseCavageSignature('Signature: keyId="",signature="b64=="')).toBeUndefined()
  })

  it('returns undefined when signature is an empty string', () => {
    expect(parseCavageSignature('Signature: keyId="alice",signature=""')).toBeUndefined()
  })

  it('returns undefined when a pair is malformed (unquoted string value)', () => {
    expect(parseCavageSignature('Signature: keyId=alice,signature="b64=="')).toBeUndefined()
  })

  it('returns undefined when keys are not separated by commas at all', () => {
    expect(parseCavageSignature('Signature: keyId="alice" signature="b64=="')).toBeUndefined()
  })
})

describe('parseRfc9421 — positive cases', () => {
  it('parses the canonical Signature-Input + Signature pair', () => {
    const input =
      'Signature-Input: sig1=("@method" "@path" "host");created=1402170695;keyid="test-key-b"'
    const sig = 'Signature: sig1=:dGVzdC1zaWduYXR1cmU=:'
    const result = parseRfc9421(input, sig)
    expect(result).toEqual({
      label: 'sig1',
      components: ['@method', '@path', 'host'],
      created: 1402170695,
      keyId: 'test-key-b',
      signature: 'dGVzdC1zaWduYXR1cmU=',
    })
  })

  it('parses the Signature-Input alone (signature header optional)', () => {
    const input =
      'Signature-Input: sig1=("@method" "@authority");created=1700000000;keyid="alice"'
    const result = parseRfc9421(input)
    expect(result?.label).toBe('sig1')
    expect(result?.signature).toBeUndefined()
    expect(result?.keyId).toBe('alice')
    expect(result?.components).toEqual(['@method', '@authority'])
  })

  it('parses the `alg` parameter (RFC 9421 allows inline algorithm)', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;keyid="alice";alg="rsa-sha256"'
    const result = parseRfc9421(input)
    expect(result?.algorithm).toBe('rsa-sha256')
  })

  it('parses the `expires` parameter', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;expires=1700003600;keyid="alice"'
    const result = parseRfc9421(input)
    expect(result?.created).toBe(1700000000)
    expect(result?.expires).toBe(1700003600)
  })

  it('parses the `nonce` parameter', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;nonce="abc123";keyid="alice"'
    const result = parseRfc9421(input)
    expect(result?.nonce).toBe('abc123')
  })

  it('handles components that include header names alongside @-prefixed derived fields', () => {
    const input =
      'Signature-Input: sig9=("@method" "@target-uri" "content-digest" "host");keyid="k"'
    const result = parseRfc9421(input)
    expect(result?.components).toEqual(['@method', '@target-uri', 'content-digest', 'host'])
  })

  it('extracts the signature from a multi-entry Signature header by label', () => {
    const input = 'Signature-Input: sig2=("@method");keyid="k"'
    const sig = 'Signature: sig1=:abcd:, sig2=:efgh:, sig3=:ijkl:'
    const result = parseRfc9421(input, sig)
    expect(result?.signature).toBe('efgh')
  })

  it('ignores a Signature header whose label does not match', () => {
    const input = 'Signature-Input: sig1=("@method");keyid="k"'
    const sig = 'Signature: other=:abcd:'
    const result = parseRfc9421(input, sig)
    expect(result?.signature).toBeUndefined()
  })

  it('ignores an empty base64 blob in the Signature header', () => {
    const input = 'Signature-Input: sig1=("@method");keyid="k"'
    const sig = 'Signature: sig1=::'
    const result = parseRfc9421(input, sig)
    expect(result?.signature).toBeUndefined()
  })

  it('is case-insensitive on the header prefix', () => {
    const input = 'signature-input: sig1=("@method");keyid="k"'
    const result = parseRfc9421(input)
    expect(result?.label).toBe('sig1')
  })

  it('tolerates parameters with extra whitespace', () => {
    const input =
      'Signature-Input: sig1=("@method") ; created = 1700000000 ; keyid = "alice"'
    const result = parseRfc9421(input)
    expect(result?.created).toBe(1700000000)
    expect(result?.keyId).toBe('alice')
  })

  it('skips unrecognised parameters silently', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;tag="ietf-fapi";keyid="alice"'
    const result = parseRfc9421(input)
    expect(result?.created).toBe(1700000000)
    expect(result?.keyId).toBe('alice')
  })

  it('skips malformed parameter chunks but keeps parsing the rest', () => {
    const input = 'Signature-Input: sig1=("@method");this-is-not-a-pair;keyid="alice"'
    const result = parseRfc9421(input)
    expect(result?.keyId).toBe('alice')
  })

  it('skips invalid created / expires (non-numeric)', () => {
    const input = 'Signature-Input: sig1=("@method");created="not-a-number";keyid="alice"'
    const result = parseRfc9421(input)
    expect(result?.created).toBeUndefined()
  })
})

describe('parseRfc9421 — negative cases', () => {
  it('returns undefined for non-string input', () => {
    expect(parseRfc9421(undefined as unknown as string)).toBeUndefined()
    expect(parseRfc9421(123 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for empty input', () => {
    expect(parseRfc9421('')).toBeUndefined()
    expect(parseRfc9421('   ')).toBeUndefined()
  })

  it('returns undefined when the inner list is missing the parens', () => {
    expect(parseRfc9421('Signature-Input: sig1=@method;keyid="k"')).toBeUndefined()
  })

  it('returns undefined when the label is missing', () => {
    expect(parseRfc9421('Signature-Input: =("@method");keyid="k"')).toBeUndefined()
  })

  it('returns undefined when the covered-component list is empty', () => {
    expect(parseRfc9421('Signature-Input: sig1=();keyid="k"')).toBeUndefined()
  })
})
