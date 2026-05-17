import { describe, expect, it } from 'vitest'
import { HttpSignatureAnalyzer } from './analyzer'

const CAVAGE_LINE =
  'Signature: keyId="alice",algorithm="rsa-sha256",headers="(request-target) host date",signature="MIIBdwIBADANBgkqhkiG9w0=="'

const CAVAGE_NO_ALG =
  'Signature: keyId="bob",headers="(request-target) host",signature="QmFzZTY0Lw=="'

const CAVAGE_WEAK =
  'Signature: keyId="alice",algorithm="hmac-sha1",signature="dGVzdA=="'

const RFC9421_INPUT =
  'Signature-Input: sig1=("@method" "@path" "host");created=1402170695;keyid="test-key-b"'

const RFC9421_SIG = 'Signature: sig1=:dGVzdC1zaWduYXR1cmU=:'

const ANALYZER = new HttpSignatureAnalyzer()

describe('HttpSignatureAnalyzer — Cavage detection', () => {
  it('matches a `Signature:` line with quoted parameters', () => {
    const text = `GET /foo HTTP/1.1\nHost: example.com\n${CAVAGE_LINE}\nAccept: */*`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text.startsWith('Signature:')).toBe(true)
  })

  it('matches a Cavage header without an algorithm', () => {
    const matches = ANALYZER.detect(CAVAGE_NO_ALG)
    expect(matches).toHaveLength(1)
  })

  it('finds multiple Cavage headers in a single document', () => {
    const text = `${CAVAGE_LINE}\n${CAVAGE_LINE}`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(2)
  })

  it('case-insensitively recognises the header name', () => {
    const lower = CAVAGE_LINE.replace('Signature:', 'signature:')
    expect(ANALYZER.detect(lower)).toHaveLength(1)
  })

  it('returns nothing for unrelated text', () => {
    expect(ANALYZER.detect('Hello, world. No headers here.')).toEqual([])
    expect(ANALYZER.detect('')).toEqual([])
  })

  it('returns nothing for a malformed Signature line that fails the parser', () => {
    // Missing the required `signature` field.
    const bad = 'Signature: keyId="alice",algorithm="rsa-sha256"'
    expect(ANALYZER.detect(bad)).toEqual([])
  })

  it('returns nothing for a Signature line missing the keyId', () => {
    const bad = 'Signature: signature="b64=="'
    expect(ANALYZER.detect(bad)).toEqual([])
  })
})

describe('HttpSignatureAnalyzer — RFC 9421 detection', () => {
  it('matches a Signature-Input + Signature pair', () => {
    const text = `POST /foo HTTP/1.1\n${RFC9421_INPUT}\n${RFC9421_SIG}\n`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text.startsWith('Signature-Input:')).toBe(true)
  })

  it('matches Signature-Input alone (signature header optional)', () => {
    const matches = ANALYZER.detect(RFC9421_INPUT)
    expect(matches).toHaveLength(1)
  })

  it('claims the paired `Signature:` line so it is not also reported as Cavage', () => {
    const text = `${RFC9421_INPUT}\n${RFC9421_SIG}`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toContain('Signature-Input')
  })

  it('returns nothing for a malformed Signature-Input', () => {
    expect(ANALYZER.detect('Signature-Input: sig1=();keyid="k"')).toEqual([])
  })
})

describe('HttpSignatureAnalyzer.analyze — Cavage', () => {
  it('produces a Signature section with the expected rows', () => {
    const [match] = ANALYZER.detect(CAVAGE_LINE)
    const result = ANALYZER.analyze(match)
    expect(result.analyzerId).toBe('httpSignature')
    expect(result.kind).toBe('HTTP Signature (Cavage)')
    expect(result.sections).toHaveLength(1)
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('variant')
    expect(keys).toContain('keyId')
    expect(keys).toContain('algorithm')
    expect(keys).toContain('headers')
    expect(keys).toContain('signature')
  })

  it('truncates the signature to the first 16 characters with an ellipsis', () => {
    const [match] = ANALYZER.detect(CAVAGE_LINE)
    const result = ANALYZER.analyze(match)
    const sigRow = result.sections[0].rows.find((r) => r.key === 'signature')
    expect(sigRow?.value).toBe('MIIBdwIBADANBgkq…')
  })

  it('does not truncate a signature shorter than 17 characters', () => {
    const short = 'Signature: keyId="alice",algorithm="rsa-sha256",signature="abc"'
    const [match] = ANALYZER.detect(short)
    const result = ANALYZER.analyze(match)
    const sigRow = result.sections[0].rows.find((r) => r.key === 'signature')
    expect(sigRow?.value).toBe('abc')
  })

  it('joins headers with a single space', () => {
    const [match] = ANALYZER.detect(CAVAGE_LINE)
    const result = ANALYZER.analyze(match)
    const headersRow = result.sections[0].rows.find((r) => r.key === 'headers')
    expect(headersRow?.value).toBe('(request-target) host date')
  })

  it('emits the algorithm.weak finding for hmac-sha1', () => {
    const [match] = ANALYZER.detect(CAVAGE_WEAK)
    const result = ANALYZER.analyze(match)
    expect(result.findings.some((f) => f.id === 'httpSignature.algorithm.weak')).toBe(true)
  })

  it('emits the algorithm.missing finding when algorithm is absent', () => {
    const [match] = ANALYZER.detect(CAVAGE_NO_ALG)
    const result = ANALYZER.analyze(match)
    expect(result.findings.some((f) => f.id === 'httpSignature.algorithm.missing')).toBe(true)
  })

  it('exposes the parsed components in the raw payload', () => {
    const [match] = ANALYZER.detect(CAVAGE_NO_ALG)
    const result = ANALYZER.analyze(match)
    expect(result.raw).toEqual({
      keyId: 'bob',
      headers: ['(request-target)', 'host'],
      signature: 'QmFzZTY0Lw==',
    })
  })

  it('renders created and expires when present', () => {
    const header =
      'Signature: keyId="alice",algorithm="rsa-sha256",created=1402170695,expires=1402170995,signature="b64=="'
    const [match] = ANALYZER.detect(header)
    const result = ANALYZER.analyze(match)
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('created')
    expect(keys).toContain('expires')
  })

  it('accepts a bare value when called via the inspect command path', () => {
    const bare = 'keyId="alice",algorithm="rsa-sha256",signature="b64=="'
    const result = ANALYZER.analyze({ text: bare })
    expect(result.kind).toBe('HTTP Signature (Cavage)')
    expect(result.sections[0].rows.find((r) => r.key === 'keyId')?.value).toBe('alice')
  })

  it('throws when given text that is not a signature header', () => {
    expect(() => ANALYZER.analyze({ text: 'not a sig at all' })).toThrow(/HTTP signature/i)
  })
})

describe('HttpSignatureAnalyzer.analyze — RFC 9421', () => {
  it('produces an RFC 9421 result with `variant`, `label`, and components rows', () => {
    const text = `${RFC9421_INPUT}\n${RFC9421_SIG}`
    const [match] = ANALYZER.detect(text)
    const result = ANALYZER.analyze(match)
    expect(result.kind).toBe('HTTP Signature (RFC 9421)')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('variant')
    expect(keys).toContain('label')
    expect(keys).toContain('components')
  })

  it('renders the components joined by spaces', () => {
    const [match] = ANALYZER.detect(RFC9421_INPUT)
    const result = ANALYZER.analyze(match)
    const componentsRow = result.sections[0].rows.find((r) => r.key === 'components')
    expect(componentsRow?.value).toBe('@method @path host')
  })

  it('surfaces the paired signature blob when both headers are passed to analyze', () => {
    // Simulate the inspect command: caller passes both lines joined by `\n`.
    const joined = `${RFC9421_INPUT}\n${RFC9421_SIG}`
    const result = ANALYZER.analyze({ text: joined })
    const sigRow = result.sections[0].rows.find((r) => r.key === 'signature')
    // 20-char base64 → truncated to 16 + ellipsis.
    expect(sigRow?.value).toBe('dGVzdC1zaWduYXR1…')
  })

  it('omits the signature row when no Signature header is paired', () => {
    const [match] = ANALYZER.detect(RFC9421_INPUT)
    const result = ANALYZER.analyze(match)
    expect(result.sections[0].rows.some((r) => r.key === 'signature')).toBe(false)
  })

  it('renders nonce and algorithm rows when present', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;keyid="alice";nonce="n123";alg="rsa-sha256"'
    const result = ANALYZER.analyze({ text: input })
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('nonce')
    expect(keys).toContain('algorithm')
  })

  it('renders created and expires rows when present', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;expires=1700003600;keyid="alice"'
    const result = ANALYZER.analyze({ text: input })
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toContain('created')
    expect(keys).toContain('expires')
  })

  it('exposes the parsed components in the raw payload', () => {
    const [match] = ANALYZER.detect(RFC9421_INPUT)
    const result = ANALYZER.analyze(match)
    expect(result.raw).toEqual({
      label: 'sig1',
      components: ['@method', '@path', 'host'],
      created: 1402170695,
      keyId: 'test-key-b',
    })
  })

  it('emits the algorithm.weak finding for an inline rsa-sha1 alg', () => {
    const input =
      'Signature-Input: sig1=("@method");created=1700000000;keyid="alice";alg="rsa-sha1"'
    const result = ANALYZER.analyze({ text: input })
    expect(result.findings.some((f) => f.id === 'httpSignature.algorithm.weak')).toBe(true)
  })

  it('throws when given text that begins with Signature-Input but is malformed', () => {
    // Empty inner list — the parser will return undefined.
    expect(() => ANALYZER.analyze({ text: 'Signature-Input: sig1=();keyid="k"' })).toThrow(/RFC 9421/i)
  })
})

describe('HttpSignatureAnalyzer.detect — interleaved Cavage + RFC 9421', () => {
  it('reports a Cavage hit + a paired RFC 9421 hit when both forms appear in the same document', () => {
    const text = `${CAVAGE_LINE}\n${RFC9421_INPUT}\n${RFC9421_SIG}\n`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(2)
    const kinds = matches.map((m) => (m.text.startsWith('Signature-Input') ? 'rfc9421' : 'cavage'))
    expect(kinds).toContain('cavage')
    expect(kinds).toContain('rfc9421')
  })
})
