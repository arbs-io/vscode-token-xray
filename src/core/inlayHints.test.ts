import { describe, expect, it } from 'vitest'
import { findingsToInlayDtos, HitRange } from './inlayHints'
import { AnalysisResult } from './types'

const HIT_RANGE: HitRange = {
  startLine: 4,
  startColumn: 0,
  endLine: 4,
  endColumn: 42,
}

function makeResult(overrides: Partial<AnalysisResult> & { analyzerId: string }): AnalysisResult {
  return {
    kind: 'detection',
    sections: [],
    findings: [],
    ...overrides,
  }
}

describe('findingsToInlayDtos', () => {
  describe('JWT / PASETO exp heuristics', () => {
    it('emits [expired] when the jwt.exp.expired finding fires', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          findings: [
            {
              id: 'jwt.exp.expired',
              severity: 'error',
              message: 'Token expired at 2020-01-01T00:00:00.000Z.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[expired]')
      expect(dtos[0].position).toEqual({ line: 4, column: 42 })
    })

    it('computes [exp in 3d] from a future numeric jwt exp claim', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const inThreeDays = Math.floor((now + 3 * 24 * 60 * 60 * 1000 + 60_000) / 1000)
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: `${inThreeDays} (${new Date(inThreeDays * 1000).toISOString()})` }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[exp in 3d]')
      expect(dtos[0].tooltip).toContain('Token expires at')
    })

    it('emits [exp tomorrow] when the token has just over a day left', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const tomorrow = Math.floor((now + 36 * 60 * 60 * 1000) / 1000)
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: `${tomorrow} (${new Date(tomorrow * 1000).toISOString()})` }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[exp tomorrow]')
    })

    it('emits [exp today] when less than 24h remain', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const inSixHours = Math.floor((now + 6 * 60 * 60 * 1000) / 1000)
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: inSixHours }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[exp today]')
    })

    it('emits [expired] when exp value is in the past but no finding fired (paseto)', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'paseto',
          kind: 'PASETO v4.public',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: '2020-01-01T00:00:00Z' }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[expired]')
    })

    it('parses an ISO-string PASETO exp claim into a relative hint', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const expIso = new Date(now + 5 * 24 * 60 * 60 * 1000 + 60_000).toISOString()
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'paseto',
          kind: 'PASETO v4.public',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: expIso }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[exp in 5d]')
    })

    it('returns no hint when the result has no exp section / row', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            { id: 'header', title: 'JOSE Header', rows: [{ key: 'alg', value: 'RS256' }] },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })

    it('returns no hint when the exp row value is not parseable as a timestamp', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: 'not-a-date' }],
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })

    it('parses a numeric-string exp value (purely numeric strings)', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const inTwoDays = Math.floor((now + 2 * 24 * 60 * 60 * 1000 + 60_000) / 1000)
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: String(inTwoDays) }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[exp in 2d]')
    })

    it('parses a millisecond-precision numeric exp value', () => {
      const now = Date.UTC(2026, 0, 1, 12, 0, 0)
      const inFourDaysMs = now + 4 * 24 * 60 * 60 * 1000 + 60_000
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'payload',
              title: 'Claims',
              rows: [{ key: 'exp', value: inFourDaysMs }],
            },
          ],
        }),
        HIT_RANGE,
        { now }
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[exp in 4d]')
    })
  })

  describe('x509 certificate heuristics', () => {
    it('emits [expired] when the validity finding fires', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'x509',
          kind: 'leaf',
          findings: [
            {
              id: 'x509.validity.expired',
              severity: 'error',
              message: 'Certificate expired at 2020-01-01T00:00:00.000Z.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[expired]')
    })

    it('emits [RSA-1024] when the weak-RSA finding fires with keyDetails', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'x509',
          kind: 'leaf',
          sections: [
            {
              id: 'certificate',
              title: 'Certificate',
              rows: [{ key: 'keyDetails', value: 'RSA-1024' }],
            },
          ],
          findings: [
            {
              id: 'x509.key.weakRsa',
              severity: 'error',
              message: 'RSA key is 1024 bits — below the 2048-bit minimum.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[RSA-1024]')
      expect(dtos[0].tooltip).toContain('1024 bits')
    })

    it('combines [expired] and [RSA-1024] when both findings fire', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'x509',
          kind: 'leaf',
          sections: [
            {
              id: 'certificate',
              title: 'Certificate',
              rows: [{ key: 'keyDetails', value: 'RSA-512' }],
            },
          ],
          findings: [
            { id: 'x509.validity.expired', severity: 'error', message: 'expired' },
            { id: 'x509.key.weakRsa', severity: 'error', message: 'RSA key is 512 bits.' },
          ],
        }),
        HIT_RANGE
      )
      const labels = dtos.map((d) => d.label).sort()
      expect(labels).toEqual(['[RSA-512]', '[expired]'])
    })

    it('falls back to parsing bits from the finding message when keyDetails is absent', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'x509',
          kind: 'leaf',
          sections: [],
          findings: [
            {
              id: 'x509.key.weakRsa',
              severity: 'error',
              message: 'RSA key is 768 bits — below the 2048-bit minimum.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[RSA-768]')
    })
  })

  describe('samlMetadata heuristics', () => {
    it('emits [expired] when a signing cert is expired', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'samlMetadata',
          kind: 'EntityDescriptor (IDPSSO)',
          findings: [
            {
              id: 'samlMeta.cert.expired',
              severity: 'error',
              message: 'Signing certificate expired at 2020-01-01.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[expired]')
    })

    it('emits [RSA-1024] when a samlMeta.cert.weakRsa finding ships with keyDetails', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'samlMetadata',
          kind: 'EntityDescriptor (IDPSSO)',
          sections: [
            {
              id: 'entity-0',
              title: 'Entity 1',
              rows: [{ key: 'keyDetails', value: 'RSA 1024' }],
            },
          ],
          findings: [
            {
              id: 'samlMeta.cert.weakRsa',
              severity: 'error',
              message: 'Signing certificate uses a 1024 bits RSA key.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[RSA-1024]')
    })

    it('returns no samlMetadata key hint when bits cannot be recovered', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'samlMetadata',
          kind: 'EntityDescriptor (IDPSSO)',
          sections: [],
          findings: [
            {
              id: 'samlMeta.cert.weakRsa',
              severity: 'error',
              message: 'Signing certificate uses a weak RSA key.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })
  })

  describe('oauth Stripe live key heuristics', () => {
    it('emits [live] when an error finding pairs with environment=live', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'oauth',
          kind: 'Stripe',
          sections: [
            {
              id: 'token',
              title: 'Token',
              rows: [
                { key: 'vendor', value: 'Stripe' },
                { key: 'environment', value: 'live' },
              ],
            },
          ],
          findings: [
            {
              id: 'oauth.stripe.secret.live',
              severity: 'error',
              message: 'Stripe LIVE secret API key.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[live]')
    })

    it('does not emit [live] for test-environment tokens', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'oauth',
          kind: 'Stripe',
          sections: [
            {
              id: 'token',
              title: 'Token',
              rows: [{ key: 'environment', value: 'test' }],
            },
          ],
          findings: [
            { id: 'oauth.stripe.secret.test', severity: 'warning', message: 'Test key' },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })

    it('does not emit [live] when the only finding is non-error severity', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'oauth',
          kind: 'Stripe',
          sections: [
            {
              id: 'token',
              title: 'Token',
              rows: [{ key: 'environment', value: 'live' }],
            },
          ],
          findings: [
            { id: 'oauth.stripe.publishable.live', severity: 'info', message: 'Publishable key.' },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })
  })

  describe('secret heuristics', () => {
    it('emits [secret] for an error-severity finding', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'secret',
          kind: 'aws',
          findings: [
            {
              id: 'aws.accessKey.AKIA',
              severity: 'error',
              message: 'AWS access key id committed to source.',
            },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toHaveLength(1)
      expect(dtos[0].label).toBe('[secret]')
      expect(dtos[0].tooltip).toContain('AWS access key')
    })

    it('does not emit [secret] when the only findings are non-error', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'secret',
          kind: 'generic',
          findings: [
            { id: 'generic.hint', severity: 'info', message: 'Looks like a token.' },
          ],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })
  })

  describe('edge cases', () => {
    it('returns an empty array for a result with no findings and no relevant sections', () => {
      const dtos = findingsToInlayDtos(
        makeResult({ analyzerId: 'jwt', kind: 'JWS' }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })

    it('returns an empty array for an unsupported analyzer id', () => {
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'basicAuth',
          kind: 'HTTP Basic',
          findings: [{ id: 'basic.cred.plaintext', severity: 'error', message: 'plaintext' }],
        }),
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })

    it('anchors every hint to the end of the hit range', () => {
      const range: HitRange = { startLine: 10, startColumn: 5, endLine: 12, endColumn: 17 }
      const dtos = findingsToInlayDtos(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          findings: [{ id: 'jwt.exp.expired', severity: 'error', message: 'expired' }],
        }),
        range
      )
      expect(dtos[0].position).toEqual({ line: 12, column: 17 })
    })

    it('handles a missing hitRange / result gracefully', () => {
      // Defensive: the provider adapter should never call us with nullish
      // inputs, but guard against the case so it cannot crash a hint pass.
      const dtos = findingsToInlayDtos(
        undefined as unknown as AnalysisResult,
        HIT_RANGE
      )
      expect(dtos).toEqual([])
    })
  })
})
