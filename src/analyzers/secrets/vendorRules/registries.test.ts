import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { REGISTRIES_SECRET_RULES } from './registries'

const opts = { rules: REGISTRIES_SECRET_RULES }

// 36 alnum chars (no `_`/`-`) for npm.
const NPM_BODY_36 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
// 43 base64url-ish chars for NuGet (contains `_` and `-` to exercise the
// full grammar).
const NUGET_BODY_43 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCde'
// 100+ base64url-ish chars for PyPI body.
const PYPI_BODY_100 =
  'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIj0123456789Hello'
// 20+ base64url-ish chars for Docker Hub PAT body.
const DOCKER_BODY_20 = 'AbCdEf012345_-XyZqWe9'
// 67 alnum chars (no `_`/`-`) for JFrog access token body. Exactly 67 — the
// rule's `{67}` quantifier is exact, so a longer alnum tail would fall foul
// of the trailing `(?![A-Za-z0-9])` lookahead.
const JFROG_BODY_67 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxY012345'

describe('REGISTRIES_SECRET_RULES — npm access token (npm_)', () => {
  it('matches npm_ + 36 alnum chars', () => {
    const text = `npm_${NPM_BODY_36}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.npm.accessToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 36 chars', () => {
    expect(
      scanForSecrets(`npm_${NPM_BODY_36.slice(0, 35)}`, opts).some(
        (h) => h.rule.id === 'secret.npm.accessToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_`/`-`)', () => {
    expect(
      scanForSecrets(`npm_${'_'.repeat(36)}`, opts).some(
        (h) => h.rule.id === 'secret.npm.accessToken'
      )
    ).toBe(false)
    expect(
      scanForSecrets(`npm_${'-'.repeat(36)}`, opts).some(
        (h) => h.rule.id === 'secret.npm.accessToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xnpm_${NPM_BODY_36}`, opts).some(
        (h) => h.rule.id === 'secret.npm.accessToken'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_npm_${NPM_BODY_36}`, opts).some(
        (h) => h.rule.id === 'secret.npm.accessToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (npx_)', () => {
    expect(
      scanForSecrets(`npx_${NPM_BODY_36}`, opts).some(
        (h) => h.rule.id === 'secret.npm.accessToken'
      )
    ).toBe(false)
  })
})

describe('REGISTRIES_SECRET_RULES — NuGet API key (oy2)', () => {
  it('matches oy2 + 43 base64url chars', () => {
    const text = `oy2${NUGET_BODY_43}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.nuget.apiKey')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 43 chars', () => {
    expect(
      scanForSecrets(`oy2${NUGET_BODY_43.slice(0, 42)}`, opts).some(
        (h) => h.rule.id === 'secret.nuget.apiKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xoy2${NUGET_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.nuget.apiKey'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_oy2${NUGET_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.nuget.apiKey'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (oy3)', () => {
    expect(
      scanForSecrets(`oy3${NUGET_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.nuget.apiKey'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`oy2${'@'.repeat(43)}`, opts).some(
        (h) => h.rule.id === 'secret.nuget.apiKey'
      )
    ).toBe(false)
  })
})

describe('REGISTRIES_SECRET_RULES — PyPI macaroon upload token', () => {
  it('matches pypi-AgEIcHlwaS5vcmc + 100+ base64url chars', () => {
    const text = `pypi-AgEIcHlwaS5vcmc${PYPI_BODY_100}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.pypi.macaroonToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 100 chars after the literal prefix', () => {
    const shortBody = 'A'.repeat(99)
    expect(
      scanForSecrets(`pypi-AgEIcHlwaS5vcmc${shortBody}`, opts).some(
        (h) => h.rule.id === 'secret.pypi.macaroonToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (pypi-AgEIcHlwaS5vcm followed by wrong continuation)', () => {
    // The literal prefix is `pypi-AgEIcHlwaS5vcmc`; truncating the trailing `c`
    // and substituting `X` must not match.
    expect(
      scanForSecrets(`pypi-AgEIcHlwaS5vcmX${PYPI_BODY_100}`, opts).some(
        (h) => h.rule.id === 'secret.pypi.macaroonToken'
      )
    ).toBe(false)
  })

  it('rejects bare `pypi-` without the AgEIcHlwaS5vcmc tail', () => {
    expect(
      scanForSecrets(`pypi-${PYPI_BODY_100}`, opts).some(
        (h) => h.rule.id === 'secret.pypi.macaroonToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xpypi-AgEIcHlwaS5vcmc${PYPI_BODY_100}`, opts).some(
        (h) => h.rule.id === 'secret.pypi.macaroonToken'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`_pypi-AgEIcHlwaS5vcmc${PYPI_BODY_100}`, opts).some(
        (h) => h.rule.id === 'secret.pypi.macaroonToken'
      )
    ).toBe(false)
  })
})

describe('REGISTRIES_SECRET_RULES — Docker Hub PAT (dckr_pat_)', () => {
  it('matches dckr_pat_ + 20-char base64url body', () => {
    const text = `dckr_pat_${DOCKER_BODY_20}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.dockerHub.pat')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 20 chars', () => {
    expect(
      scanForSecrets(`dckr_pat_${'A'.repeat(19)}`, opts).some(
        (h) => h.rule.id === 'secret.dockerHub.pat'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xdckr_pat_${DOCKER_BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.dockerHub.pat'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_dckr_pat_${DOCKER_BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.dockerHub.pat'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (dckr_token_)', () => {
    expect(
      scanForSecrets(`dckr_token_${DOCKER_BODY_20}`, opts).some(
        (h) => h.rule.id === 'secret.dockerHub.pat'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`dckr_pat_${'@'.repeat(20)}`, opts).some(
        (h) => h.rule.id === 'secret.dockerHub.pat'
      )
    ).toBe(false)
  })
})

describe('REGISTRIES_SECRET_RULES — JFrog Artifactory access token (AKCp)', () => {
  it('matches AKCp + 67 alnum chars', () => {
    const text = `AKCp${JFROG_BODY_67}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.jfrog.accessToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 67 chars', () => {
    expect(
      scanForSecrets(`AKCp${JFROG_BODY_67.slice(0, 66)}`, opts).some(
        (h) => h.rule.id === 'secret.jfrog.accessToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_`/`-`)', () => {
    expect(
      scanForSecrets(`AKCp${'_'.repeat(67)}`, opts).some(
        (h) => h.rule.id === 'secret.jfrog.accessToken'
      )
    ).toBe(false)
    expect(
      scanForSecrets(`AKCp${'-'.repeat(67)}`, opts).some(
        (h) => h.rule.id === 'secret.jfrog.accessToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xAKCp${JFROG_BODY_67}`, opts).some(
        (h) => h.rule.id === 'secret.jfrog.accessToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (AKCQ instead of AKCp)', () => {
    expect(
      scanForSecrets(`AKCQ${JFROG_BODY_67}`, opts).some(
        (h) => h.rule.id === 'secret.jfrog.accessToken'
      )
    ).toBe(false)
  })
})

describe('REGISTRIES_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of REGISTRIES_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of REGISTRIES_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('every rule carries error severity', () => {
    for (const r of REGISTRIES_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = REGISTRIES_SECRET_RULES.map((r) => r.id).sort((a, b) => a.localeCompare(b))
    expect(ids).toEqual([
      'secret.dockerHub.pat',
      'secret.jfrog.accessToken',
      'secret.npm.accessToken',
      'secret.nuget.apiKey',
      'secret.pypi.macaroonToken',
    ])
  })
})
