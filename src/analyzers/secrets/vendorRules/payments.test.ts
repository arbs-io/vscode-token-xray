import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { PAYMENTS_SECRET_RULES } from './payments'

const opts = { rules: PAYMENTS_SECRET_RULES }

// 60 base64url-ish chars (contains `_` and `-` to exercise the full grammar)
// for the Square access token body — the rule requires at least 60.
const SQUARE_ACCESS_BODY_60 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKl0123456789'
// 43 base64url-ish chars for the Square application secret body. Exactly 43
// — the rule's `{43}` quantifier is exact, so a longer base64url tail would
// fall foul of the trailing `(?![A-Za-z0-9_-])` lookahead.
const SQUARE_APP_SECRET_BODY_43 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCde'
// 22 base64url-ish chars for the Square application id body.
const SQUARE_APP_ID_BODY_22 = 'AbCdEfGhIjKl0123456_-X'
// PayPal client-id half (lowercase alnum) and 32-hex suffix.
const PAYPAL_CLIENT_ID = 'aaaaaaaaaaaabbbbbbbbbbbbcccccccc'
const PAYPAL_HEX_32 = '0123456789abcdef0123456789abcdef'

describe('PAYMENTS_SECRET_RULES — Square access token (EAAA…)', () => {
  it('matches EAAA + 60 base64url chars', () => {
    const text = `EAAA${SQUARE_ACCESS_BODY_60}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.square.accessToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches longer bodies (>60 base64url chars)', () => {
    const longerBody = SQUARE_ACCESS_BODY_60 + 'xyz_-012'
    expect(
      scanForSecrets(`EAAA${longerBody}`, opts).some(
        (h) => h.rule.id === 'secret.square.accessToken'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 60 chars', () => {
    expect(
      scanForSecrets(`EAAA${SQUARE_ACCESS_BODY_60.slice(0, 59)}`, opts).some(
        (h) => h.rule.id === 'secret.square.accessToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`EAAA${'@'.repeat(60)}`, opts).some(
        (h) => h.rule.id === 'secret.square.accessToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xEAAA${SQUARE_ACCESS_BODY_60}`, opts).some(
        (h) => h.rule.id === 'secret.square.accessToken'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_EAAA${SQUARE_ACCESS_BODY_60}`, opts).some(
        (h) => h.rule.id === 'secret.square.accessToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (EAAB)', () => {
    expect(
      scanForSecrets(`EAAB${SQUARE_ACCESS_BODY_60}`, opts).some(
        (h) => h.rule.id === 'secret.square.accessToken'
      )
    ).toBe(false)
  })
})

describe('PAYMENTS_SECRET_RULES — Square application secret (sq0csp-)', () => {
  it('matches sq0csp- + 43 base64url chars', () => {
    const text = `sq0csp-${SQUARE_APP_SECRET_BODY_43}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.square.appSecret'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 43 chars', () => {
    expect(
      scanForSecrets(`sq0csp-${SQUARE_APP_SECRET_BODY_43.slice(0, 42)}`, opts).some(
        (h) => h.rule.id === 'secret.square.appSecret'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`sq0csp-${'@'.repeat(43)}`, opts).some(
        (h) => h.rule.id === 'secret.square.appSecret'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xsq0csp-${SQUARE_APP_SECRET_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.square.appSecret'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_sq0csp-${SQUARE_APP_SECRET_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.square.appSecret'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (sq0idp- — application id, not secret)', () => {
    expect(
      scanForSecrets(`sq0xsp-${SQUARE_APP_SECRET_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.square.appSecret'
      )
    ).toBe(false)
  })
})

describe('PAYMENTS_SECRET_RULES — Square application id (sq0idp-)', () => {
  it('matches sq0idp- + 22 base64url chars at info severity', () => {
    const text = `sq0idp-${SQUARE_APP_ID_BODY_22}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.square.appId')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 22 chars', () => {
    expect(
      scanForSecrets(`sq0idp-${SQUARE_APP_ID_BODY_22.slice(0, 21)}`, opts).some(
        (h) => h.rule.id === 'secret.square.appId'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`sq0idp-${'@'.repeat(22)}`, opts).some(
        (h) => h.rule.id === 'secret.square.appId'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xsq0idp-${SQUARE_APP_ID_BODY_22}`, opts).some(
        (h) => h.rule.id === 'secret.square.appId'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (sq0csp- — application secret, not id)', () => {
    expect(
      scanForSecrets(`sq0xdp-${SQUARE_APP_ID_BODY_22}`, opts).some(
        (h) => h.rule.id === 'secret.square.appId'
      )
    ).toBe(false)
  })
})

describe('PAYMENTS_SECRET_RULES — PayPal long-form access token', () => {
  it('matches access_token$production$<clientId>$<32-hex>', () => {
    const text = `access_token$production$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.paypal.accessToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches access_token$sandbox$<clientId>$<32-hex>', () => {
    const text = `access_token$sandbox$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(true)
  })

  it('rejects an unknown environment label (e.g. staging)', () => {
    expect(
      scanForSecrets(
        `access_token$staging$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })

  it('rejects hex suffix shorter than 32 chars', () => {
    expect(
      scanForSecrets(
        `access_token$production$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32.slice(0, 31)}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })

  it('rejects hex suffix outside [a-f0-9] (e.g. uppercase or g)', () => {
    expect(
      scanForSecrets(
        `access_token$production$${PAYPAL_CLIENT_ID}$${'g'.repeat(32)}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
    expect(
      scanForSecrets(
        `access_token$production$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32.toUpperCase()}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })

  it('rejects client-id chars outside [a-z0-9] (e.g. uppercase)', () => {
    expect(
      scanForSecrets(
        `access_token$production$${PAYPAL_CLIENT_ID.toUpperCase()}$${PAYPAL_HEX_32}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })

  it('rejects prefix mismatch (refresh_token$…)', () => {
    expect(
      scanForSecrets(
        `refresh_token$production$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(
        `xaccess_token$production$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(
        `x_access_token$production$${PAYPAL_CLIENT_ID}$${PAYPAL_HEX_32}`,
        opts
      ).some((h) => h.rule.id === 'secret.paypal.accessToken')
    ).toBe(false)
  })
})

describe('PAYMENTS_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of PAYMENTS_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of PAYMENTS_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('Square access token / app secret and PayPal access token carry error severity', () => {
    const errorIds = new Set(
      PAYMENTS_SECRET_RULES.filter((r) => r.severity === 'error').map((r) => r.id)
    )
    expect(errorIds.has('secret.square.accessToken')).toBe(true)
    expect(errorIds.has('secret.square.appSecret')).toBe(true)
    expect(errorIds.has('secret.paypal.accessToken')).toBe(true)
  })

  it('Square application id is info severity (identifier, not secret on its own)', () => {
    const appId = PAYMENTS_SECRET_RULES.find((r) => r.id === 'secret.square.appId')
    expect(appId?.severity).toBe('info')
  })

  it('exposes the expected rule ids', () => {
    const ids = PAYMENTS_SECRET_RULES.map((r) => r.id).sort()
    expect(ids).toEqual([
      'secret.paypal.accessToken',
      'secret.square.accessToken',
      'secret.square.appId',
      'secret.square.appSecret',
    ])
  })
})
