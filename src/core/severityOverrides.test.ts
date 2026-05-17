import { describe, expect, it } from 'vitest'
import { applySeverityOverrides, SeverityOverrideMap } from './severityOverrides'
import { Finding } from './types'

function f(overrides: Partial<Finding> & { id: string }): Finding {
  return {
    severity: 'warning',
    message: 'msg',
    ...overrides,
  }
}

describe('applySeverityOverrides', () => {
  describe('input guards', () => {
    it('returns [] for nullish findings', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(applySeverityOverrides(undefined as any, {})).toEqual([])
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(applySeverityOverrides(null as any, {})).toEqual([])
    })

    it('returns an empty array for empty findings input', () => {
      expect(applySeverityOverrides([], { 'jwt.alg.none': 'off' })).toEqual([])
    })

    it('returns a copy of findings when overrides is empty', () => {
      const findings = [f({ id: 'jwt.alg.none' })]
      const out = applySeverityOverrides(findings, {})
      expect(out).toEqual(findings)
      expect(out).not.toBe(findings)
    })

    it('tolerates nullish overrides map', () => {
      const findings = [f({ id: 'jwt.alg.none' })]
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const out = applySeverityOverrides(findings, undefined as any)
      expect(out).toEqual(findings)
      expect(out).not.toBe(findings)
    })

    it('never mutates the input findings array', () => {
      const findings = [
        f({ id: 'jwt.alg.none', severity: 'warning' }),
        f({ id: 'secret.aws.akid', severity: 'error' }),
      ]
      const snapshot = structuredClone(findings)
      applySeverityOverrides(findings, {
        'jwt.alg.none': 'error',
        'secret.aws.akid': 'off',
      })
      expect(findings).toEqual(snapshot)
    })

    it('ignores override values that are not one of the four allowed strings', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'warning' })]
      const out = applySeverityOverrides(findings, {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        'jwt.alg.none': 'bogus' as any,
      })
      // bogus override is dropped → finding passes through unchanged.
      expect(out).toEqual(findings)
    })

    it('ignores non-string override values', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'warning' })]
      const out = applySeverityOverrides(findings, {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        'jwt.alg.none': 42 as any,
      })
      expect(out).toEqual(findings)
    })

    it('ignores the empty-string key', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'warning' })]
      const out = applySeverityOverrides(findings, { '': 'off' })
      expect(out).toEqual(findings)
    })

    it('ignores the bare `.*` wildcard so it never silences everything', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'warning' })]
      const out = applySeverityOverrides(findings, { '.*': 'off' })
      expect(out).toEqual(findings)
    })
  })

  describe('off — drops findings', () => {
    it('removes a finding when the override is `off`', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'warning' })]
      expect(applySeverityOverrides(findings, { 'jwt.alg.none': 'off' })).toEqual([])
    })

    it('keeps findings not listed when another id is `off`', () => {
      const findings = [
        f({ id: 'jwt.alg.none', severity: 'warning' }),
        f({ id: 'secret.aws.akid', severity: 'error' }),
      ]
      expect(
        applySeverityOverrides(findings, { 'jwt.alg.none': 'off' })
      ).toEqual([f({ id: 'secret.aws.akid', severity: 'error' })])
    })
  })

  describe('error / warning / info — mutates severity', () => {
    it('rewrites a `warning` finding to `error`', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'warning' })]
      const out = applySeverityOverrides(findings, { 'jwt.alg.none': 'error' })
      expect(out).toHaveLength(1)
      expect(out[0]).toEqual(f({ id: 'jwt.alg.none', severity: 'error' }))
      // input must remain unchanged
      expect(findings[0].severity).toBe('warning')
    })

    it('rewrites an `error` finding to `warning`', () => {
      const findings = [f({ id: 'secret.aws.akid', severity: 'error' })]
      const out = applySeverityOverrides(findings, { 'secret.aws.akid': 'warning' })
      expect(out).toEqual([f({ id: 'secret.aws.akid', severity: 'warning' })])
    })

    it('rewrites a `warning` finding to `info`', () => {
      const findings = [f({ id: 'oauth.github.pat', severity: 'warning' })]
      const out = applySeverityOverrides(findings, { 'oauth.github.pat': 'info' })
      expect(out).toEqual([f({ id: 'oauth.github.pat', severity: 'info' })])
    })

    it('preserves auxiliary fields (message, range, docUrl) when rewriting severity', () => {
      const findings: Finding[] = [
        {
          id: 'jwt.alg.none',
          severity: 'warning',
          message: 'alg=none token',
          range: { start: 4, end: 12 },
          docUrl: 'https://example/jwt-alg-none',
        },
      ]
      const out = applySeverityOverrides(findings, { 'jwt.alg.none': 'error' })
      expect(out[0]).toEqual({
        id: 'jwt.alg.none',
        severity: 'error',
        message: 'alg=none token',
        range: { start: 4, end: 12 },
        docUrl: 'https://example/jwt-alg-none',
      })
    })

    it('passes the finding through unchanged when override equals existing severity', () => {
      const findings = [f({ id: 'jwt.alg.none', severity: 'error' })]
      const out = applySeverityOverrides(findings, { 'jwt.alg.none': 'error' })
      // identity-preserved for the no-op match
      expect(out).toHaveLength(1)
      expect(out[0]).toBe(findings[0])
    })
  })

  describe('wildcard prefix', () => {
    it('drops every finding under the prefix when set to `off`', () => {
      const findings = [
        f({ id: 'secret.aws.akid', severity: 'error' }),
        f({ id: 'secret.gcp.serviceAccount', severity: 'error' }),
        f({ id: 'secret.privateKey.pem', severity: 'error' }),
        f({ id: 'jwt.alg.none', severity: 'warning' }),
      ]
      const out = applySeverityOverrides(findings, { 'secret.*': 'off' })
      expect(out).toEqual([f({ id: 'jwt.alg.none', severity: 'warning' })])
    })

    it('rewrites every finding under the prefix to a new severity', () => {
      const findings = [
        f({ id: 'secret.aws.akid', severity: 'error' }),
        f({ id: 'secret.gcp.apiKey', severity: 'error' }),
        f({ id: 'jwt.alg.none', severity: 'warning' }),
      ]
      const out = applySeverityOverrides(findings, { 'secret.*': 'warning' })
      expect(out).toEqual([
        f({ id: 'secret.aws.akid', severity: 'warning' }),
        f({ id: 'secret.gcp.apiKey', severity: 'warning' }),
        f({ id: 'jwt.alg.none', severity: 'warning' }),
      ])
    })

    it('matches the bare prefix (`prefix` alone) as well as `prefix.<rest>`', () => {
      const findings = [
        f({ id: 'secret', severity: 'error' }),
        f({ id: 'secret.aws.akid', severity: 'error' }),
      ]
      const out = applySeverityOverrides(findings, { 'secret.*': 'off' })
      expect(out).toEqual([])
    })

    it('does not match ids that merely start with the prefix string (no dot boundary)', () => {
      const findings = [
        f({ id: 'secretive.foo', severity: 'warning' }), // not under secret.*
        f({ id: 'secret.aws.akid', severity: 'error' }),
      ]
      const out = applySeverityOverrides(findings, { 'secret.*': 'off' })
      expect(out).toEqual([f({ id: 'secretive.foo', severity: 'warning' })])
    })

    it('uses the longest matching prefix when wildcards overlap', () => {
      // `secret.aws.*` is more specific than `secret.*` → its value wins.
      const findings = [
        f({ id: 'secret.aws.akid', severity: 'error' }),
        f({ id: 'secret.gcp.apiKey', severity: 'error' }),
      ]
      const out = applySeverityOverrides(findings, {
        'secret.*': 'off',
        'secret.aws.*': 'info',
      })
      // secret.aws.akid → info, secret.gcp.apiKey → off (dropped)
      expect(out).toEqual([f({ id: 'secret.aws.akid', severity: 'info' })])
    })
  })

  describe('exact-over-wildcard precedence', () => {
    it('an exact id match wins over a matching wildcard (off vs. mutate)', () => {
      const findings = [
        f({ id: 'secret.aws.akid', severity: 'error' }),
        f({ id: 'secret.gcp.apiKey', severity: 'error' }),
      ]
      const out = applySeverityOverrides(findings, {
        'secret.*': 'off',
        'secret.aws.akid': 'warning',
      })
      // aws.akid → warning (exact wins), gcp.apiKey → dropped (wildcard).
      expect(out).toEqual([f({ id: 'secret.aws.akid', severity: 'warning' })])
    })

    it('an exact id match wins over a matching wildcard (mutate vs. off)', () => {
      const findings = [f({ id: 'secret.aws.akid', severity: 'error' })]
      const out = applySeverityOverrides(findings, {
        'secret.aws.akid': 'off',
        'secret.*': 'error',
      })
      // exact override is `off` → the finding is dropped.
      expect(out).toEqual([])
    })
  })

  describe('no-op pass-through', () => {
    it('returns findings unchanged when no rule matches', () => {
      const findings = [
        f({ id: 'jwt.alg.none', severity: 'warning' }),
        f({ id: 'secret.aws.akid', severity: 'error' }),
      ]
      const out = applySeverityOverrides(findings, {
        'oauth.github.pat': 'info',
        'paseto.*': 'off',
      })
      expect(out).toEqual(findings)
    })

    it('handles a mixed batch of pass-through / mutate / drop', () => {
      const findings = [
        f({ id: 'jwt.alg.none', severity: 'warning' }),
        f({ id: 'secret.aws.akid', severity: 'error' }),
        f({ id: 'paseto.version.deprecated', severity: 'info' }),
        f({ id: 'cookie.secure.missing', severity: 'warning' }),
      ]
      const overrides: SeverityOverrideMap = {
        'jwt.alg.none': 'error', // mutate
        'secret.*': 'off', // drop
        'paseto.*': 'warning', // mutate via wildcard
        // cookie.secure.missing → pass-through
      }
      const out = applySeverityOverrides(findings, overrides)
      expect(out).toEqual([
        f({ id: 'jwt.alg.none', severity: 'error' }),
        f({ id: 'paseto.version.deprecated', severity: 'warning' }),
        f({ id: 'cookie.secure.missing', severity: 'warning' }),
      ])
    })
  })
})
