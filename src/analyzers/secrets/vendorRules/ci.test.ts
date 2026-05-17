import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { CI_SECRET_RULES } from './ci'

const opts = { rules: CI_SECRET_RULES }

// 40 base64url-ish chars (contains `_` and `-` to exercise the full grammar)
// for the CircleCI PAT body.
const CCI_BODY_40 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Ab'
// 52 alnum chars (no `_`/`-`) for the Buildkite agent token body. Exactly 52
// — the rule's `{52}` quantifier is exact, so a longer alnum tail would fall
// foul of the trailing `(?![A-Za-z0-9])` lookahead.
const BKA_BODY_52 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl0123'
// 40 alnum chars (no `_`/`-`) for the Buildkite API token body.
const BKUA_BODY_40 = 'AbCdEfGhIjKlMnOpQrStUvWxYz01234567890123'
// UUID-shaped Codecov upload token (8-4-4-4-12 lowercase hex with hyphens).
const CODECOV_UUID = 'a1b2c3d4-e5f6-7890-abcd-ef0123456789'

describe('CI_SECRET_RULES — CircleCI PAT (CCIPAT_)', () => {
  it('matches CCIPAT_ + 40 base64url chars', () => {
    const text = `CCIPAT_${CCI_BODY_40}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.circleci.pat')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches longer bodies (>40 base64url chars)', () => {
    const longerBody = CCI_BODY_40 + 'xyz_-012'
    expect(
      scanForSecrets(`CCIPAT_${longerBody}`, opts).some(
        (h) => h.rule.id === 'secret.circleci.pat'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 40 chars', () => {
    expect(
      scanForSecrets(`CCIPAT_${CCI_BODY_40.slice(0, 39)}`, opts).some(
        (h) => h.rule.id === 'secret.circleci.pat'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xCCIPAT_${CCI_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.circleci.pat'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_CCIPAT_${CCI_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.circleci.pat'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (CCIPATX_ instead of CCIPAT_)', () => {
    expect(
      scanForSecrets(`CCIPATX_${CCI_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.circleci.pat'
      )
    ).toBe(false)
  })
})

describe('CI_SECRET_RULES — Buildkite agent token (bka_)', () => {
  it('matches bka_ + 52 alnum chars', () => {
    const text = `bka_${BKA_BODY_52}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.buildkite.agentToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 52 chars', () => {
    expect(
      scanForSecrets(`bka_${BKA_BODY_52.slice(0, 51)}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.agentToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_`/`-`)', () => {
    expect(
      scanForSecrets(`bka_${'_'.repeat(52)}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.agentToken'
      )
    ).toBe(false)
    expect(
      scanForSecrets(`bka_${'-'.repeat(52)}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.agentToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xbka_${BKA_BODY_52}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.agentToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (bk_ instead of bka_)', () => {
    expect(
      scanForSecrets(`bk_${BKA_BODY_52}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.agentToken'
      )
    ).toBe(false)
  })

  it('does not collide with bkua_ (API token prefix)', () => {
    // A bkua_-shaped token must not match the agent rule. bkua_ + 40 alnum is
    // exactly the API token shape — `bka_` would need 52 alnum chars after it.
    expect(
      scanForSecrets(`bkua_${BKUA_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.agentToken'
      )
    ).toBe(false)
  })
})

describe('CI_SECRET_RULES — Buildkite API token (bkua_)', () => {
  it('matches bkua_ + 40 alnum chars', () => {
    const text = `bkua_${BKUA_BODY_40}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.buildkite.apiToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 40 chars', () => {
    expect(
      scanForSecrets(`bkua_${BKUA_BODY_40.slice(0, 39)}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.apiToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_`/`-`)', () => {
    expect(
      scanForSecrets(`bkua_${'_'.repeat(40)}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.apiToken'
      )
    ).toBe(false)
    expect(
      scanForSecrets(`bkua_${'-'.repeat(40)}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.apiToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xbkua_${BKUA_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.apiToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (bkub_ instead of bkua_)', () => {
    expect(
      scanForSecrets(`bkub_${BKUA_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.apiToken'
      )
    ).toBe(false)
  })

  it('does not collide with bka_ (agent token prefix)', () => {
    expect(
      scanForSecrets(`bka_${BKA_BODY_52}`, opts).some(
        (h) => h.rule.id === 'secret.buildkite.apiToken'
      )
    ).toBe(false)
  })
})

describe('CI_SECRET_RULES — Codecov upload token (labelled)', () => {
  it('matches CODECOV_TOKEN=<uuid>', () => {
    const text = `CODECOV_TOKEN=${CODECOV_UUID}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(CODECOV_UUID)
  })

  it('matches CODECOV_UPLOAD_TOKEN=<uuid>', () => {
    expect(
      scanForSecrets(`CODECOV_UPLOAD_TOKEN=${CODECOV_UUID}`, opts).some(
        (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
      )
    ).toBe(true)
  })

  it('matches JSON-shaped "codecovToken": "<uuid>"', () => {
    expect(
      scanForSecrets(`{ "codecovToken": "${CODECOV_UUID}" }`, opts).some(
        (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
      )
    ).toBe(true)
  })

  it('rejects malformed UUID (missing hyphen segments)', () => {
    expect(
      scanForSecrets(`CODECOV_TOKEN=${CODECOV_UUID.replace(/-/g, '')}`, opts).some(
        (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Codecov UUIDs are lowercase)', () => {
    expect(
      scanForSecrets(`CODECOV_TOKEN=${CODECOV_UUID.toUpperCase()}`, opts).some(
        (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
      )
    ).toBe(false)
  })

  it('does not flag a bare UUID without the label', () => {
    expect(
      scanForSecrets(CODECOV_UUID, opts).some(
        (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects label mismatch (CODECOV_KEY=…)', () => {
    expect(
      scanForSecrets(`CODECOV_KEY=${CODECOV_UUID}`, opts).some(
        (h) => h.rule.id === 'secret.codecov.uploadTokenLabelled'
      )
    ).toBe(false)
  })
})

describe('CI_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of CI_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of CI_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('every rule carries error severity', () => {
    for (const r of CI_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = CI_SECRET_RULES.map((r) => r.id).sort()
    expect(ids).toEqual([
      'secret.buildkite.agentToken',
      'secret.buildkite.apiToken',
      'secret.circleci.pat',
      'secret.codecov.uploadTokenLabelled',
    ])
  })
})
