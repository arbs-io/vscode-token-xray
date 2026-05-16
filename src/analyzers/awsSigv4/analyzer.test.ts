import { describe, expect, it } from 'vitest'
import { AwsSigv4Analyzer } from './analyzer'

const VALID_HEADER_LINE =
  'Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024'

const VALID_STANDALONE =
  'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024'

const ANALYZER = new AwsSigv4Analyzer()

describe('AwsSigv4Analyzer — header-prefixed detection', () => {
  it('matches `Authorization: AWS4-HMAC-SHA256 …`', () => {
    const text = `GET /api HTTP/1.1\n${VALID_HEADER_LINE}\nAccept: */*`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].text).toContain('AWS4-HMAC-SHA256')
    expect(matches[0].range?.start).toBe(text.indexOf('Authorization'))
  })

  it('matches case-insensitively', () => {
    const lower = VALID_HEADER_LINE.replace('Authorization', 'authorization')
    expect(ANALYZER.detect(lower)).toHaveLength(1)
  })

  it('matches when the header uses = instead of : (curl -H reps)', () => {
    const swapped = VALID_HEADER_LINE.replace('Authorization:', 'Authorization=')
    expect(ANALYZER.detect(swapped)).toHaveLength(1)
  })

  it('returns nothing for plain text or empty input', () => {
    expect(ANALYZER.detect('hello world')).toEqual([])
    expect(ANALYZER.detect('')).toEqual([])
  })

  it('returns nothing for an Authorization Bearer header', () => {
    expect(ANALYZER.detect('Authorization: Bearer eyJhbGciOi…')).toEqual([])
  })

  it('finds multiple SigV4 headers in a single document', () => {
    const text = `${VALID_HEADER_LINE}\n${VALID_HEADER_LINE}`
    expect(ANALYZER.detect(text)).toHaveLength(2)
  })

  it('skips header-prefixed matches whose value fails the structural parser', () => {
    // Algorithm token present + Credential= present, but malformed scope.
    const bad =
      'Authorization: AWS4-HMAC-SHA256 Credential=AKIA/bad/scope, SignedHeaders=host, Signature=abc'
    expect(ANALYZER.detect(bad)).toEqual([])
  })
})

describe('AwsSigv4Analyzer — standalone (no Authorization prefix) detection', () => {
  it('matches a bare AWS4-HMAC-SHA256 line containing all three markers', () => {
    const matches = ANALYZER.detect(VALID_STANDALONE)
    expect(matches).toHaveLength(1)
    expect(matches[0].text.startsWith('AWS4-HMAC-SHA256')).toBe(true)
  })

  it('matches a standalone line embedded in a wider document', () => {
    const text = `# Example SigV4 request\n${VALID_STANDALONE}\n# end`
    const matches = ANALYZER.detect(text)
    expect(matches).toHaveLength(1)
    // Range must point at the AWS4 token, not at the preceding newline.
    expect(text.slice(matches[0].range!.start, matches[0].range!.end)).toBe(VALID_STANDALONE)
  })

  it('does NOT double-match the header-prefixed form via the standalone regex', () => {
    // The first-claim-wins logic must keep us to one finding when both
    // patterns can match overlapping ranges.
    const matches = ANALYZER.detect(VALID_HEADER_LINE)
    expect(matches).toHaveLength(1)
  })

  it('returns nothing when the line is missing the SignedHeaders marker', () => {
    const incomplete =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, Signature=fe5f80'
    expect(ANALYZER.detect(incomplete)).toEqual([])
  })

  it('returns nothing when the line is missing the Signature marker', () => {
    const incomplete =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host'
    expect(ANALYZER.detect(incomplete)).toEqual([])
  })

  it('returns nothing when the line is missing the Credential marker', () => {
    const incomplete = 'AWS4-HMAC-SHA256 SignedHeaders=host, Signature=fe5f80'
    expect(ANALYZER.detect(incomplete)).toEqual([])
  })

  it('returns nothing when the standalone line fails parser validation', () => {
    const bad =
      'AWS4-HMAC-SHA256 Credential=AKIA/bad/scope/x, SignedHeaders=host, Signature=abc'
    expect(ANALYZER.detect(bad)).toEqual([])
  })
})

describe('AwsSigv4Analyzer.analyze', () => {
  it('produces a Signature section with all six rows', () => {
    const [match] = ANALYZER.detect(VALID_HEADER_LINE)
    const result = ANALYZER.analyze(match)
    expect(result.analyzerId).toBe('awsSigv4')
    expect(result.kind).toBe('AWS SigV4')
    expect(result.sections).toHaveLength(1)
    expect(result.sections[0].id).toBe('signature')
    const keys = result.sections[0].rows.map((r) => r.key)
    expect(keys).toEqual(['accessKeyId', 'region', 'service', 'date', 'signedHeaders', 'signature'])
  })

  it('joins signedHeaders with `;` and truncates the signature to 8 chars + ellipsis', () => {
    const [match] = ANALYZER.detect(VALID_HEADER_LINE)
    const result = ANALYZER.analyze(match)
    const rows = Object.fromEntries(result.sections[0].rows.map((r) => [r.key, r.value]))
    expect(rows.signedHeaders).toBe('host;range;x-amz-date')
    expect(rows.signature).toBe('fe5f80f7…')
  })

  it('does not truncate a signature shorter than 8 characters', () => {
    const short =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123'
    const [match] = ANALYZER.detect(short)
    const result = ANALYZER.analyze(match)
    const sig = result.sections[0].rows.find((r) => r.key === 'signature')
    expect(sig?.value).toBe('abc123')
  })

  it('emits awsSigv4.accessKeyExposed for every detected header', () => {
    const [match] = ANALYZER.detect(VALID_HEADER_LINE)
    const result = ANALYZER.analyze(match)
    const exposed = result.findings.find((f) => f.id === 'awsSigv4.accessKeyExposed')
    expect(exposed?.severity).toBe('warning')
  })

  it('emits awsSigv4.session.token for ASIA keys', () => {
    const asia = VALID_HEADER_LINE.replace('AKIAIOSFODNN7EXAMPLE', 'ASIAIOSFODNN7EXAMPLE')
    const [match] = ANALYZER.detect(asia)
    const result = ANALYZER.analyze(match)
    expect(result.findings.some((f) => f.id === 'awsSigv4.session.token')).toBe(true)
  })

  it('emits awsSigv4.signedHeaders.missingHost when host is not signed', () => {
    const noHost = VALID_HEADER_LINE.replace('host;range;x-amz-date', 'range;x-amz-date')
    const [match] = ANALYZER.detect(noHost)
    const result = ANALYZER.analyze(match)
    expect(result.findings.some((f) => f.id === 'awsSigv4.signedHeaders.missingHost')).toBe(true)
  })

  it('analyzes a standalone (no Authorization prefix) match correctly', () => {
    const [match] = ANALYZER.detect(VALID_STANDALONE)
    const result = ANALYZER.analyze(match)
    expect(result.sections[0].rows.find((r) => r.key === 'accessKeyId')?.value).toBe('AKIAIOSFODNN7EXAMPLE')
  })

  it('accepts a bare credential value when called directly (inspect command path)', () => {
    const result = ANALYZER.analyze({ text: VALID_STANDALONE })
    expect(result.sections[0].rows.find((r) => r.key === 'region')?.value).toBe('us-east-1')
  })

  it('accepts the full Authorization: form when called directly', () => {
    const result = ANALYZER.analyze({ text: VALID_HEADER_LINE })
    expect(result.sections[0].rows.find((r) => r.key === 'service')?.value).toBe('s3')
  })

  it('throws when given a string that is not a SigV4 header', () => {
    expect(() => ANALYZER.analyze({ text: 'not a sigv4 header at all' })).toThrow(/AWS SigV4/i)
  })

  it('exposes the parsed components in the raw payload', () => {
    const [match] = ANALYZER.detect(VALID_HEADER_LINE)
    const result = ANALYZER.analyze(match)
    expect(result.raw).toEqual({
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      date: '20130524',
      region: 'us-east-1',
      service: 's3',
      signedHeaders: ['host', 'range', 'x-amz-date'],
      signature: 'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024',
    })
  })
})
