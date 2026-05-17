import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { COMMS_SECRET_RULES } from './comms'

const opts = { rules: COMMS_SECRET_RULES }

// 32-hex bodies for Twilio account-SID / API-key-SID / auth token.
const HEX_32 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'

// SendGrid envelope: 22 base64url + `.` + 43 base64url.
const SG_B22 = 'AbCdEfGhIjKlMnOpQrStUv' // 22 chars
const SG_B43 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCde' // 43 chars

// Telegram bot hash: exactly 35 base64url chars.
const TG_HASH_35 = 'AAaaBBbbCCccDDddEEee0011223344-_aaa' // 35 chars

// Discord shape: <M|N><23 alnum>.<6 b64url>.<27 b64url>.
const DC_HEAD_24 = 'M' + 'A'.repeat(23) // 24 chars, starts with M
const DC_TS_6 = 'A1b2C3'
const DC_HMAC_27 = 'A'.repeat(20) + 'bcdefgh' // 27 chars

describe('COMMS_SECRET_RULES — Twilio Account SID', () => {
  it('matches AC + 32 lowercase hex (info severity)', () => {
    const text = `AC${HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.twilio.accountSid'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(`AC${HEX_32}`)
  })

  it('rejects body shorter than 32 hex chars', () => {
    expect(
      scanForSecrets(`AC${HEX_32.slice(0, 31)}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.accountSid'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex in body (Twilio SIDs are lowercase)', () => {
    expect(
      scanForSecrets(`AC${'A'.repeat(32)}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.accountSid'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`xAC${HEX_32}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.accountSid'
      )
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — Twilio API Key SID', () => {
  it('matches SK + 32 lowercase hex (error severity)', () => {
    const text = `SK${HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.twilio.apiKeySid'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(`SK${HEX_32}`)
  })

  it('rejects body shorter than 32 chars', () => {
    expect(
      scanForSecrets(`SK${HEX_32.slice(0, 31)}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.apiKeySid'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex in body', () => {
    expect(
      scanForSecrets(`SK${'A'.repeat(32)}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.apiKeySid'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`xSK${HEX_32}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.apiKeySid'
      )
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — Twilio auth token (labelled)', () => {
  it('matches TWILIO_AUTH_TOKEN=<32 hex>', () => {
    const text = `TWILIO_AUTH_TOKEN=${HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.twilio.authTokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX_32)
  })

  it('matches camelCase twilioAuthToken: "<hex>"', () => {
    expect(
      scanForSecrets(`{ "twilioAuthToken": "${HEX_32}" }`, opts).some(
        (h) => h.rule.id === 'secret.twilio.authTokenLabelled'
      )
    ).toBe(true)
  })

  it('rejects body that is not 32 hex chars', () => {
    expect(
      scanForSecrets('TWILIO_AUTH_TOKEN=short', opts).some(
        (h) => h.rule.id === 'secret.twilio.authTokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Twilio auth tokens are lowercase)', () => {
    expect(
      scanForSecrets(`TWILIO_AUTH_TOKEN=${'A'.repeat(32)}`, opts).some(
        (h) => h.rule.id === 'secret.twilio.authTokenLabelled'
      )
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — SendGrid API key', () => {
  it('matches SG.<22>.<43>', () => {
    const text = `SG.${SG_B22}.${SG_B43}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.sendgrid.apiKey'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects SG. with body lengths outside 22/43', () => {
    // 21 + 43
    expect(
      scanForSecrets(`SG.${SG_B22.slice(0, 21)}.${SG_B43}`, opts).some(
        (h) => h.rule.id === 'secret.sendgrid.apiKey'
      )
    ).toBe(false)
    // 22 + 42
    expect(
      scanForSecrets(`SG.${SG_B22}.${SG_B43.slice(0, 42)}`, opts).some(
        (h) => h.rule.id === 'secret.sendgrid.apiKey'
      )
    ).toBe(false)
  })

  it('rejects body chars outside base64url (e.g. `@`)', () => {
    expect(
      scanForSecrets(`SG.${'@'.repeat(22)}.${SG_B43}`, opts).some(
        (h) => h.rule.id === 'secret.sendgrid.apiKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer base64url identifier', () => {
    expect(
      scanForSecrets(`xSG.${SG_B22}.${SG_B43}`, opts).some(
        (h) => h.rule.id === 'secret.sendgrid.apiKey'
      )
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — Mailgun API key', () => {
  it('matches key-<32 hex>', () => {
    const text = `key-${HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.mailgun.apiKey'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 32 hex chars', () => {
    expect(
      scanForSecrets(`key-${HEX_32.slice(0, 31)}`, opts).some(
        (h) => h.rule.id === 'secret.mailgun.apiKey'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex in body', () => {
    expect(
      scanForSecrets(`key-${'A'.repeat(32)}`, opts).some(
        (h) => h.rule.id === 'secret.mailgun.apiKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier', () => {
    expect(
      scanForSecrets(`api-key-${HEX_32}`, opts).some(
        (h) => h.rule.id === 'secret.mailgun.apiKey'
      )
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — Telegram bot token', () => {
  it('matches <8-10 digit bot id>:<35 char hash>', () => {
    const text = `123456789:${TG_HASH_35}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.telegram.botToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches a 10-digit bot id', () => {
    expect(
      scanForSecrets(`1234567890:${TG_HASH_35}`, opts).some(
        (h) => h.rule.id === 'secret.telegram.botToken'
      )
    ).toBe(true)
  })

  it('rejects phone-number-like prefix with short body (1234567890:short)', () => {
    expect(
      scanForSecrets('1234567890:short', opts).some(
        (h) => h.rule.id === 'secret.telegram.botToken'
      )
    ).toBe(false)
  })

  it('rejects body shorter than 35 chars', () => {
    expect(
      scanForSecrets(`123456789:${TG_HASH_35.slice(0, 34)}`, opts).some(
        (h) => h.rule.id === 'secret.telegram.botToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`123456789:${'@'.repeat(35)}`, opts).some(
        (h) => h.rule.id === 'secret.telegram.botToken'
      )
    ).toBe(false)
  })

  it('rejects bot id shorter than 8 digits', () => {
    expect(
      scanForSecrets(`1234567:${TG_HASH_35}`, opts).some(
        (h) => h.rule.id === 'secret.telegram.botToken'
      )
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — Discord bot token', () => {
  it('matches three base64url segments joined by `.` (M-prefixed)', () => {
    const text = `${DC_HEAD_24}.${DC_TS_6}.${DC_HMAC_27}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.discord.botToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches an N-prefixed bot token (newer user-id encoding)', () => {
    const head = 'N' + 'A'.repeat(23)
    expect(
      scanForSecrets(`${head}.${DC_TS_6}.${DC_HMAC_27}`, opts).some(
        (h) => h.rule.id === 'secret.discord.botToken'
      )
    ).toBe(true)
  })

  it('rejects prefix character outside [MN]', () => {
    const head = 'Z' + 'A'.repeat(23)
    expect(
      scanForSecrets(`${head}.${DC_TS_6}.${DC_HMAC_27}`, opts).some(
        (h) => h.rule.id === 'secret.discord.botToken'
      )
    ).toBe(false)
  })

  it('rejects head segment shorter than 24 chars', () => {
    const shortHead = 'M' + 'A'.repeat(22) // 23
    expect(
      scanForSecrets(`${shortHead}.${DC_TS_6}.${DC_HMAC_27}`, opts).some(
        (h) => h.rule.id === 'secret.discord.botToken'
      )
    ).toBe(false)
  })

  it('rejects HMAC segment shorter than 27 chars', () => {
    expect(
      scanForSecrets(`${DC_HEAD_24}.${DC_TS_6}.${DC_HMAC_27.slice(0, 26)}`, opts).some(
        (h) => h.rule.id === 'secret.discord.botToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer base64url identifier', () => {
    const text = `x${DC_HEAD_24}.${DC_TS_6}.${DC_HMAC_27}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.discord.botToken')
    ).toBe(false)
  })
})

describe('COMMS_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of COMMS_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of COMMS_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = COMMS_SECRET_RULES.map((r) => r.id).sort((a, b) => a.localeCompare(b))
    expect(ids).toEqual([
      'secret.discord.botToken',
      'secret.mailgun.apiKey',
      'secret.sendgrid.apiKey',
      'secret.telegram.botToken',
      'secret.twilio.accountSid',
      'secret.twilio.apiKeySid',
      'secret.twilio.authTokenLabelled',
    ])
  })

  it('account SID is info severity (identifies account, not a secret)', () => {
    const r = COMMS_SECRET_RULES.find((x) => x.id === 'secret.twilio.accountSid')
    expect(r?.severity).toBe('info')
  })

  it('all other rules carry error severity', () => {
    for (const r of COMMS_SECRET_RULES) {
      if (r.id === 'secret.twilio.accountSid') continue
      expect(r.severity).toBe('error')
    }
  })
})
