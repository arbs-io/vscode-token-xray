import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { ATLASSIAN_SECRET_RULES } from './atlassian'

const opts = { rules: ATLASSIAN_SECRET_RULES }

// Real Atlassian Cloud API tokens are ~192 chars: 12-char prefix + ~180 body +
// 8-char checksum. Build a representative sample within those bounds.
const ATATT_PREFIX = 'ATATT3xFfGF0'
const ATATT_BODY_180 = 'A'.repeat(60) + 'b'.repeat(60) + '0123456789'.repeat(6) // 180
const ATATT_CHECKSUM_8 = '1A2b3C4d' // 8 alnum chars (no `_`/`-`)
const ATATT_TOKEN = `${ATATT_PREFIX}${ATATT_BODY_180}${ATATT_CHECKSUM_8}`

const LABELLED_VALUE_16 = 'A'.repeat(8) + 'b'.repeat(4) + '0123' // 16
const LABELLED_VALUE_20 = LABELLED_VALUE_16 + 'WxYz' // 20

describe('ATLASSIAN_SECRET_RULES — Atlassian Cloud API token', () => {
  it('matches a 200-char ATATT3xFfGF0 token (12 prefix + 180 body + 8 checksum)', () => {
    const text = ATATT_TOKEN
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.atlassian.apiToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(ATATT_TOKEN)
  })

  it('matches token body containing base64-url body characters (_=+-)', () => {
    // 40 + 4 (specials) + 40 + 90 (10*9) + 6 = 180
    const body = 'A'.repeat(40) + '_-=+' + 'b'.repeat(40) + '0123456789'.repeat(9) + 'abcdef'
    expect(body.length).toBe(180)
    const token = `${ATATT_PREFIX}${body}${ATATT_CHECKSUM_8}`
    expect(
      scanForSecrets(token, opts).some((h) => h.rule.id === 'secret.atlassian.apiToken')
    ).toBe(true)
  })

  it('rejects a too-short body (only 100 body chars + 8 checksum)', () => {
    const shortBody = 'a'.repeat(100)
    const text = `${ATATT_PREFIX}${shortBody}${ATATT_CHECKSUM_8}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.atlassian.apiToken')
    ).toBe(false)
  })

  it('rejects a bare ATATT3xFfGF0 prefix without any body', () => {
    expect(
      scanForSecrets(ATATT_PREFIX, opts).some((h) => h.rule.id === 'secret.atlassian.apiToken')
    ).toBe(false)
  })

  it('rejects similar but unrelated prefixes (e.g. ATATT_OTHER)', () => {
    // The literal prefix is `ATATT3xFfGF0`; an underscore after `ATATT` breaks
    // the format and must never match.
    const text = `ATATT_OTHER_${'a'.repeat(180)}${ATATT_CHECKSUM_8}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.atlassian.apiToken')
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    // Negative-lookbehind anchor: identifier-context tokens (e.g. inside a
    // variable name) must not be reported.
    const text = `MY${ATATT_TOKEN}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.atlassian.apiToken')
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    const text = `_${ATATT_TOKEN}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.atlassian.apiToken')
    ).toBe(false)
  })
})

describe('ATLASSIAN_SECRET_RULES — JIRA_API_TOKEN labelled', () => {
  it('matches JIRA_API_TOKEN=<value> with sensitiveSpan over the value', () => {
    const text = `JIRA_API_TOKEN=${LABELLED_VALUE_16}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.atlassian.jiraApiTokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(LABELLED_VALUE_16)
  })

  it('matches quoted JSON `"jiraApiToken": "<value>"`', () => {
    const text = `{"jiraApiToken": "${LABELLED_VALUE_16}"}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.atlassian.jiraApiTokenLabelled')
    ).toBe(true)
  })

  it('rejects empty value `JIRA_API_TOKEN=`', () => {
    expect(
      scanForSecrets('JIRA_API_TOKEN=', opts).some(
        (h) => h.rule.id === 'secret.atlassian.jiraApiTokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects a too-short value', () => {
    expect(
      scanForSecrets('JIRA_API_TOKEN=short', opts).some(
        (h) => h.rule.id === 'secret.atlassian.jiraApiTokenLabelled'
      )
    ).toBe(false)
  })
})

describe('ATLASSIAN_SECRET_RULES — CONFLUENCE_API_TOKEN labelled', () => {
  it('matches CONFLUENCE_API_TOKEN=<value> with sensitiveSpan over the value', () => {
    const text = `CONFLUENCE_API_TOKEN=${LABELLED_VALUE_16}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.atlassian.confluenceApiTokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(LABELLED_VALUE_16)
  })

  it('matches quoted JSON `"confluenceApiToken": "<value>"`', () => {
    const text = `{"confluenceApiToken": "${LABELLED_VALUE_16}"}`
    expect(
      scanForSecrets(text, opts).some(
        (h) => h.rule.id === 'secret.atlassian.confluenceApiTokenLabelled'
      )
    ).toBe(true)
  })

  it('rejects empty value `CONFLUENCE_API_TOKEN=`', () => {
    expect(
      scanForSecrets('CONFLUENCE_API_TOKEN=', opts).some(
        (h) => h.rule.id === 'secret.atlassian.confluenceApiTokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects a too-short value', () => {
    expect(
      scanForSecrets('CONFLUENCE_API_TOKEN=short', opts).some(
        (h) => h.rule.id === 'secret.atlassian.confluenceApiTokenLabelled'
      )
    ).toBe(false)
  })
})

describe('ATLASSIAN_SECRET_RULES — ATLASSIAN_OAUTH_CLIENT_SECRET labelled', () => {
  it('matches ATLASSIAN_OAUTH_CLIENT_SECRET=<value> with sensitiveSpan over the value', () => {
    const text = `ATLASSIAN_OAUTH_CLIENT_SECRET=${LABELLED_VALUE_20}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.atlassian.oauthClientSecretLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(LABELLED_VALUE_20)
  })

  it('matches quoted JSON `"atlassianOauthClientSecret": "<value>"`', () => {
    const text = `{"atlassianOauthClientSecret": "${LABELLED_VALUE_20}"}`
    expect(
      scanForSecrets(text, opts).some(
        (h) => h.rule.id === 'secret.atlassian.oauthClientSecretLabelled'
      )
    ).toBe(true)
  })

  it('rejects empty value `ATLASSIAN_OAUTH_CLIENT_SECRET=`', () => {
    expect(
      scanForSecrets('ATLASSIAN_OAUTH_CLIENT_SECRET=', opts).some(
        (h) => h.rule.id === 'secret.atlassian.oauthClientSecretLabelled'
      )
    ).toBe(false)
  })

  it('rejects a too-short value (under 20 chars)', () => {
    expect(
      scanForSecrets(`ATLASSIAN_OAUTH_CLIENT_SECRET=${'a'.repeat(10)}`, opts).some(
        (h) => h.rule.id === 'secret.atlassian.oauthClientSecretLabelled'
      )
    ).toBe(false)
  })
})

describe('ATLASSIAN_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of ATLASSIAN_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.atlassian', () => {
    for (const r of ATLASSIAN_SECRET_RULES) {
      expect(r.id.startsWith('secret.atlassian.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('all rules carry error severity', () => {
    for (const r of ATLASSIAN_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = ATLASSIAN_SECRET_RULES.map((r) => r.id).sort((a, b) => a.localeCompare(b))
    expect(ids).toEqual([
      'secret.atlassian.apiToken',
      'secret.atlassian.confluenceApiTokenLabelled',
      'secret.atlassian.jiraApiTokenLabelled',
      'secret.atlassian.oauthClientSecretLabelled',
    ])
  })
})
