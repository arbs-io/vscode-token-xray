import { describe, expect, it } from 'vitest'
import { parseSigv4Authorization } from './parser'

const VALID_LONG_TERM =
  'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024'

const VALID_SESSION =
  'AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20240101/eu-west-2/iam/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=abc123def456'

describe('parseSigv4Authorization — positive cases', () => {
  it('parses a canonical long-term credential header (bare value)', () => {
    const result = parseSigv4Authorization(VALID_LONG_TERM)
    expect(result).toEqual({
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      date: '20130524',
      region: 'us-east-1',
      service: 's3',
      signedHeaders: ['host', 'range', 'x-amz-date'],
      signature: 'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024',
    })
  })

  it('strips a leading "Authorization:" prefix', () => {
    const result = parseSigv4Authorization(`Authorization: ${VALID_LONG_TERM}`)
    expect(result?.accessKeyId).toBe('AKIAIOSFODNN7EXAMPLE')
  })

  it('tolerates "Authorization=" separator (some curl reps / logs)', () => {
    const result = parseSigv4Authorization(`Authorization=${VALID_LONG_TERM}`)
    expect(result?.region).toBe('us-east-1')
  })

  it('parses an ASIA STS session credential', () => {
    const result = parseSigv4Authorization(VALID_SESSION)
    expect(result?.accessKeyId).toBe('ASIAIOSFODNN7EXAMPLE')
    expect(result?.signedHeaders).toContain('x-amz-security-token')
  })

  it('lower-cases the signature and signedHeaders', () => {
    const mixed =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=Host;X-Amz-Date, Signature=FE5F80F77D5FA3BECA038A248FF027D0'
    const result = parseSigv4Authorization(mixed)
    expect(result?.signature).toBe('fe5f80f77d5fa3beca038a248ff027d0')
    expect(result?.signedHeaders).toEqual(['host', 'x-amz-date'])
  })

  it('tolerates extra whitespace around commas and equals signs', () => {
    const spaced =
      'AWS4-HMAC-SHA256 Credential = AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request , SignedHeaders = host;x-amz-date , Signature = abc123'
    const result = parseSigv4Authorization(spaced)
    expect(result?.accessKeyId).toBe('AKIAIOSFODNN7EXAMPLE')
    expect(result?.signedHeaders).toEqual(['host', 'x-amz-date'])
  })

  it('accepts services with hyphens (e.g. execute-api)', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/execute-api/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)?.service).toBe('execute-api')
  })
})

describe('parseSigv4Authorization — negative cases', () => {
  it('returns undefined for non-string input', () => {
    expect(parseSigv4Authorization(undefined as unknown as string)).toBeUndefined()
    expect(parseSigv4Authorization(null as unknown as string)).toBeUndefined()
    expect(parseSigv4Authorization(123 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for empty / whitespace input', () => {
    expect(parseSigv4Authorization('')).toBeUndefined()
    expect(parseSigv4Authorization('   ')).toBeUndefined()
  })

  it('returns undefined when the algorithm is not AWS4-HMAC-SHA256', () => {
    expect(parseSigv4Authorization('AWS4-HMAC-SHA512 Credential=AKIA…')).toBeUndefined()
    expect(parseSigv4Authorization('Bearer eyJhbGc…')).toBeUndefined()
  })

  it('returns undefined when Credential= is missing', () => {
    const header = 'AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when SignedHeaders= is missing', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when Signature= is missing', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the credential scope has too few parts', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the credential scope has too many parts', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/extra/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the terminator is not aws4_request', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws5_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the access key prefix is wrong (not AKIA/ASIA)', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AGPAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the access key is too short', () => {
    // AKIA + 8 chars = 12 chars total — below the minimum.
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAABCDEFGH/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the access key contains lowercase letters', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAiosfodnn7example/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the date is not 8 digits', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/2013-05-24/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the region is empty', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524//s3/aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the service is empty', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1//aws4_request, SignedHeaders=host, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when SignedHeaders is empty after splitting', () => {
    // ';' alone gives no non-empty entries; the field is also required to
    // not be blank by the outer regex (Signature must still match).
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=;;;, Signature=abc'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })

  it('returns undefined when the signature is not hex', () => {
    const header =
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=not-hex-z'
    expect(parseSigv4Authorization(header)).toBeUndefined()
  })
})
