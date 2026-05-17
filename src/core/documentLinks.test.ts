import { describe, expect, it } from 'vitest'
import { extractDocumentLinks, HitRange } from './documentLinks'
import { AnalysisResult } from './types'

const HIT_RANGE: HitRange = {
  startLine: 2,
  startColumn: 4,
  endLine: 2,
  endColumn: 96,
}

function makeResult(overrides: Partial<AnalysisResult> & { analyzerId: string }): AnalysisResult {
  return {
    kind: 'detection',
    sections: [],
    findings: [],
    ...overrides,
  }
}

describe('extractDocumentLinks', () => {
  it('emits a link for every finding.docUrl', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        findings: [
          {
            id: 'jwt.idp.okta',
            severity: 'info',
            message: 'Okta issuer recognised',
            docUrl: 'https://developer.okta.com/docs/concepts/auth-servers/',
          },
          {
            id: 'jwt.alg.none',
            severity: 'error',
            message: 'alg=none rejected',
            docUrl: 'https://datatracker.ietf.org/doc/html/rfc7519',
          },
        ],
      }),
      HIT_RANGE,
      'eyJhbGciOi...'
    )
    expect(links).toHaveLength(2)
    expect(links[0]).toEqual({
      target: 'https://developer.okta.com/docs/concepts/auth-servers/',
      range: HIT_RANGE,
    })
    expect(links[1].target).toBe('https://datatracker.ietf.org/doc/html/rfc7519')
    // The range objects are independent copies so the provider can mutate
    // them without leaking back into the analyzer result.
    expect(links[0].range).not.toBe(HIT_RANGE)
  })

  it('emits a link for an iss claim row whose value is an https URL', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        sections: [
          {
            id: 'payload',
            title: 'Claims',
            rows: [
              { key: 'sub', value: 'alice' },
              { key: 'iss', value: 'https://login.microsoftonline.com/contoso/v2.0' },
            ],
          },
        ],
      }),
      HIT_RANGE,
      'eyJhbGciOi...'
    )
    expect(links).toHaveLength(1)
    expect(links[0].target).toBe('https://login.microsoftonline.com/contoso/v2.0')
    expect(links[0].range).toEqual(HIT_RANGE)
  })

  it('emits links for both finding docUrls AND iss claim in one result', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        findings: [
          {
            id: 'jwt.idp.entraV2',
            severity: 'info',
            message: 'Entra ID issuer',
            docUrl: 'https://learn.microsoft.com/azure/active-directory/develop/access-tokens',
          },
        ],
        sections: [
          {
            id: 'payload',
            title: 'Claims',
            rows: [{ key: 'iss', value: 'https://login.microsoftonline.com/contoso/v2.0' }],
          },
        ],
      }),
      HIT_RANGE,
      'eyJhbGciOi...'
    )
    expect(links).toHaveLength(2)
    const targets = links.map((l) => l.target)
    expect(targets).toContain(
      'https://learn.microsoft.com/azure/active-directory/develop/access-tokens'
    )
    expect(targets).toContain('https://login.microsoftonline.com/contoso/v2.0')
  })

  it('returns an empty array when there are neither docUrls nor iss claims', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        findings: [
          { id: 'jwt.kid.missing', severity: 'warning', message: 'kid missing' },
        ],
        sections: [
          {
            id: 'payload',
            title: 'Claims',
            rows: [{ key: 'sub', value: 'alice' }],
          },
        ],
      }),
      HIT_RANGE,
      'eyJhbGciOi...'
    )
    expect(links).toEqual([])
  })

  it('deduplicates identical target+range pairs', () => {
    const sharedUrl = 'https://datatracker.ietf.org/doc/html/rfc7519'
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        findings: [
          { id: 'jwt.alg.none', severity: 'error', message: 'alg=none', docUrl: sharedUrl },
          { id: 'jwt.alg.weak', severity: 'warning', message: 'alg=HS256', docUrl: sharedUrl },
        ],
        sections: [
          {
            id: 'payload',
            title: 'Claims',
            rows: [{ key: 'iss', value: sharedUrl }],
          },
        ],
      }),
      HIT_RANGE,
      'eyJhbGciOi...'
    )
    expect(links).toHaveLength(1)
    expect(links[0].target).toBe(sharedUrl)
  })

  it('skips iss rows whose value is not an https string', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        sections: [
          {
            id: 'payload',
            title: 'Claims',
            rows: [
              { key: 'iss', value: 'http://insecure.example.com/' },
              { key: 'iss', value: 'plain-issuer-name' },
              { key: 'iss', value: 42 },
              { key: 'iss', value: null },
              { key: 'iss', value: ['https://example.com/'] },
            ],
          },
        ],
      }),
      HIT_RANGE,
      ''
    )
    expect(links).toEqual([])
  })

  it('skips findings without a docUrl', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'secret',
        kind: 'secret',
        findings: [
          { id: 'secret.aws.accessKey', severity: 'error', message: 'AWS key' },
          {
            id: 'secret.aws.secretKey',
            severity: 'error',
            message: 'AWS secret',
            docUrl: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
          },
        ],
      }),
      HIT_RANGE,
      'AKIAIOSFODNN7EXAMPLE'
    )
    expect(links).toHaveLength(1)
    expect(links[0].target).toBe(
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
    )
  })

  it('ignores non-iss rows even when their value looks like a URL', () => {
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'oauth',
        kind: 'oauth',
        sections: [
          {
            id: 'token',
            title: 'Token',
            rows: [
              { key: 'docsUrl', value: 'https://docs.example.com/' },
              { key: 'audience', value: 'https://api.example.com/' },
            ],
          },
        ],
      }),
      HIT_RANGE,
      ''
    )
    expect(links).toEqual([])
  })

  it('returns an empty array when result or hitRange is missing', () => {
    expect(
      extractDocumentLinks(undefined as unknown as AnalysisResult, HIT_RANGE, '')
    ).toEqual([])
    expect(
      extractDocumentLinks(
        makeResult({ analyzerId: 'jwt', kind: 'JWS' }),
        undefined as unknown as HitRange,
        ''
      )
    ).toEqual([])
  })

  it('tolerates a result with no findings or sections arrays', () => {
    const result = {
      analyzerId: 'jwt',
      kind: 'JWS',
    } as unknown as AnalysisResult
    expect(extractDocumentLinks(result, HIT_RANGE, '')).toEqual([])
  })

  it('does not extract any URLs from the raw token text body itself', () => {
    // Even when the raw body contains a URL substring (which can happen for
    // SAML XML or JWK JSON dumps), the coarse-range design means the helper
    // only ever emits findings + iss links — never URLs lifted from the body.
    const links = extractDocumentLinks(
      makeResult({
        analyzerId: 'jwt',
        kind: 'JWS',
        findings: [],
        sections: [],
      }),
      HIT_RANGE,
      'eyJ...{"iss":"https://login.microsoftonline.com/contoso/v2.0"}...'
    )
    expect(links).toEqual([])
  })
})
