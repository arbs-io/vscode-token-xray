import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { GITLAB_SECRET_RULES } from './gitlab'

const opts = { rules: GITLAB_SECRET_RULES }

// Body charsets: PAT / runner / deploy / feature-flag / CI tokens use
// base64url-ish `[A-Za-z0-9_-]`. Compose 20+ chars including `_` and `-`
// to exercise the full grammar.
const BODY_20 = 'AbCdEf012345_-XyZqWe' // 20 chars, mixed case + digits + `_-`
const SHORT_BODY = 'AbCdEf01234' // 11 chars — under the 20-char minimum
const OAUTH_HEX_64 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'

describe('GITLAB_SECRET_RULES — personal access token (glpat-)', () => {
  it('matches glpat- with a 20-char base64url body', () => {
    const text = `glpat-${BODY_20}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.gitlab.pat')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects a too-short body (< 20 chars)', () => {
    expect(
      scanForSecrets(`glpat-${SHORT_BODY}`, opts).some((h) => h.rule.id === 'secret.gitlab.pat')
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    const text = `x_glpat-${BODY_20}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.gitlab.pat')).toBe(false)
  })

  it('rejects body characters outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`glpat-AbCdEf012345@@@XyZqWe`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.pat'
      )
    ).toBe(false)
  })
})

describe('GITLAB_SECRET_RULES — OAuth access token (gloas-)', () => {
  it('matches gloas- + 64 hex chars', () => {
    const text = `gloas-${OAUTH_HEX_64}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.gitlab.oauth')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects too-short hex body (63 chars)', () => {
    const text = `gloas-${OAUTH_HEX_64.slice(0, 63)}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.gitlab.oauth')).toBe(false)
  })

  it('rejects non-hex chars (uppercase A-F)', () => {
    const upper = 'A'.repeat(64)
    expect(
      scanForSecrets(`gloas-${upper}`, opts).some((h) => h.rule.id === 'secret.gitlab.oauth')
    ).toBe(false)
  })

  it('rejects body chars outside hex (e.g. `@`)', () => {
    const body = '@'.repeat(64)
    expect(
      scanForSecrets(`gloas-${body}`, opts).some((h) => h.rule.id === 'secret.gitlab.oauth')
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    const text = `x_gloas-${OAUTH_HEX_64}`
    expect(scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.gitlab.oauth')).toBe(false)
  })
})

describe('GITLAB_SECRET_RULES — runner authentication token (glrt-)', () => {
  it('matches glrt- with a 20-char body', () => {
    const text = `glrt-${BODY_20}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.gitlab.runnerToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects a too-short body (< 20 chars)', () => {
    expect(
      scanForSecrets(`glrt-${SHORT_BODY}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.runnerToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-]', () => {
    expect(
      scanForSecrets(`glrt-AbCdEf012345@@@XyZqWe`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.runnerToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`x_glrt-${BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.runnerToken'
      )
    ).toBe(false)
  })
})

describe('GITLAB_SECRET_RULES — deploy token (gldt-)', () => {
  it('matches gldt- with a 20-char body', () => {
    const text = `gldt-${BODY_20}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.gitlab.deployToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects a too-short body (< 20 chars)', () => {
    expect(
      scanForSecrets(`gldt-${SHORT_BODY}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.deployToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-]', () => {
    expect(
      scanForSecrets(`gldt-AbCdEf012345@@@XyZqWe`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.deployToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`x_gldt-${BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.deployToken'
      )
    ).toBe(false)
  })
})

describe('GITLAB_SECRET_RULES — feature flag client token (glffct-)', () => {
  it('matches glffct- with a 20-char body', () => {
    const text = `glffct-${BODY_20}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.gitlab.featureFlagClientToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects a too-short body (< 20 chars)', () => {
    expect(
      scanForSecrets(`glffct-${SHORT_BODY}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.featureFlagClientToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-]', () => {
    expect(
      scanForSecrets(`glffct-AbCdEf012345@@@XyZqWe`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.featureFlagClientToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`x_glffct-${BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.featureFlagClientToken'
      )
    ).toBe(false)
  })
})

describe('GITLAB_SECRET_RULES — CI/CD job token (glcbt-)', () => {
  it('matches glcbt- with a 20-char body', () => {
    const text = `glcbt-${BODY_20}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.gitlab.cicdJobToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects a too-short body (< 20 chars)', () => {
    expect(
      scanForSecrets(`glcbt-${SHORT_BODY}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.cicdJobToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-]', () => {
    expect(
      scanForSecrets(`glcbt-AbCdEf012345@@@XyZqWe`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.cicdJobToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`x_glcbt-${BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.gitlab.cicdJobToken'
      )
    ).toBe(false)
  })
})

describe('GITLAB_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of GITLAB_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.gitlab', () => {
    for (const r of GITLAB_SECRET_RULES) {
      expect(r.id.startsWith('secret.gitlab.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('all rules carry error severity', () => {
    for (const r of GITLAB_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = GITLAB_SECRET_RULES.map((r) => r.id).sort((a, b) => a.localeCompare(b))
    expect(ids).toEqual([
      'secret.gitlab.cicdJobToken',
      'secret.gitlab.deployToken',
      'secret.gitlab.featureFlagClientToken',
      'secret.gitlab.oauth',
      'secret.gitlab.pat',
      'secret.gitlab.runnerToken',
    ])
  })
})
