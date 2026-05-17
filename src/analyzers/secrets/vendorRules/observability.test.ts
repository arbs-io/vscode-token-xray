import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { OBSERVABILITY_SECRET_RULES } from './observability'

const opts = { rules: OBSERVABILITY_SECRET_RULES }

// 32 / 40 lowercase-hex bodies (Datadog API + APP, Sentry DSN key).
const HEX_32 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
const HEX_40 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'

// 27-char uppercase-alphanumeric body for New Relic NRA*-… keys.
const NR_BODY_27 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0' // 27 chars (26 letters + 1 digit)

// 20-char PagerDuty body across the full alphabet (letters + digits + `_+-`).
const PD_BODY_20 = 'A1bcdef_+-ABC0123xyz' // 20 chars

describe('OBSERVABILITY_SECRET_RULES — Datadog API key (labelled)', () => {
  it('matches DD_API_KEY=<32 hex>', () => {
    const text = `DD_API_KEY=${HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.datadog.apiKeyLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX_32)
  })

  it('matches DATADOG_API_KEY=<32 hex>', () => {
    expect(
      scanForSecrets(`DATADOG_API_KEY=${HEX_32}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.apiKeyLabelled'
      )
    ).toBe(true)
  })

  it('matches JSON-shaped "datadogApiKey": "<hex>"', () => {
    expect(
      scanForSecrets(`{ "datadogApiKey": "${HEX_32}" }`, opts).some(
        (h) => h.rule.id === 'secret.datadog.apiKeyLabelled'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 32 hex chars', () => {
    expect(
      scanForSecrets(`DD_API_KEY=${HEX_32.slice(0, 31)}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.apiKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Datadog keys are lowercase)', () => {
    expect(
      scanForSecrets(`DD_API_KEY=${'A'.repeat(32)}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.apiKeyLabelled'
      )
    ).toBe(false)
  })

  it('does not flag a bare 32-hex string without the label', () => {
    expect(
      scanForSecrets(HEX_32, opts).some(
        (h) => h.rule.id === 'secret.datadog.apiKeyLabelled'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — Datadog APP key (labelled)', () => {
  it('matches DD_APP_KEY=<40 hex>', () => {
    const text = `DD_APP_KEY=${HEX_40}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.datadog.appKeyLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX_40)
  })

  it('matches DATADOG_APP_KEY=<40 hex>', () => {
    expect(
      scanForSecrets(`DATADOG_APP_KEY=${HEX_40}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.appKeyLabelled'
      )
    ).toBe(true)
  })

  it('matches DD_APPLICATION_KEY=<40 hex>', () => {
    expect(
      scanForSecrets(`DD_APPLICATION_KEY=${HEX_40}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.appKeyLabelled'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 40 hex chars', () => {
    expect(
      scanForSecrets(`DD_APP_KEY=${HEX_40.slice(0, 39)}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.appKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex in body', () => {
    expect(
      scanForSecrets(`DD_APP_KEY=${'A'.repeat(40)}`, opts).some(
        (h) => h.rule.id === 'secret.datadog.appKeyLabelled'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — New Relic user key (NRAK-)', () => {
  it('matches NRAK- + 27 uppercase-alnum chars', () => {
    const text = `NRAK-${NR_BODY_27}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.newRelic.userKey'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects wrong-prefix NRBK-…', () => {
    expect(
      scanForSecrets(`NRBK-${NR_BODY_27}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.userKey'
      )
    ).toBe(false)
  })

  it('rejects body shorter than 27 chars', () => {
    expect(
      scanForSecrets(`NRAK-${NR_BODY_27.slice(0, 26)}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.userKey'
      )
    ).toBe(false)
  })

  it('rejects lowercase chars in body (NRAK uppercase-only)', () => {
    expect(
      scanForSecrets(`NRAK-${'a'.repeat(27)}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.userKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in identifier context', () => {
    expect(
      scanForSecrets(`xNRAK-${NR_BODY_27}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.userKey'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — New Relic ingest key (NRAA-)', () => {
  it('matches NRAA- + 27 uppercase-alnum chars', () => {
    const text = `NRAA-${NR_BODY_27}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.newRelic.ingestKey'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects wrong-prefix NRBK-…', () => {
    expect(
      scanForSecrets(`NRBK-${NR_BODY_27}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.ingestKey'
      )
    ).toBe(false)
  })

  it('rejects body shorter than 27 chars', () => {
    expect(
      scanForSecrets(`NRAA-${NR_BODY_27.slice(0, 26)}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.ingestKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in identifier context', () => {
    expect(
      scanForSecrets(`xNRAA-${NR_BODY_27}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.ingestKey'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — New Relic license key (NRAL-)', () => {
  it('matches NRAL- + 27 uppercase-alnum chars', () => {
    const text = `NRAL-${NR_BODY_27}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.newRelic.licenseKey'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects wrong-prefix NRBK-…', () => {
    expect(
      scanForSecrets(`NRBK-${NR_BODY_27}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.licenseKey'
      )
    ).toBe(false)
  })

  it('rejects body shorter than 27 chars', () => {
    expect(
      scanForSecrets(`NRAL-${NR_BODY_27.slice(0, 26)}`, opts).some(
        (h) => h.rule.id === 'secret.newRelic.licenseKey'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — Sentry DSN', () => {
  it('matches https://<32-hex>@o123.ingest.sentry.io/4567', () => {
    const text = `https://${HEX_32}@o123.ingest.sentry.io/4567`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.sentry.dsn')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    // sensitiveSpan covers only the 32-hex secret half, not the host.
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX_32)
  })

  it('matches DSN without the o<digits>./ingest. host segments', () => {
    expect(
      scanForSecrets(`https://${HEX_32}@sentry.io/42`, opts).some(
        (h) => h.rule.id === 'secret.sentry.dsn'
      )
    ).toBe(true)
  })

  it('matches DSN with just the ingest. host segment', () => {
    expect(
      scanForSecrets(`https://${HEX_32}@ingest.sentry.io/9999`, opts).some(
        (h) => h.rule.id === 'secret.sentry.dsn'
      )
    ).toBe(true)
  })

  it('rejects DSN missing the sentry.io host suffix', () => {
    expect(
      scanForSecrets(`https://${HEX_32}@example.com/4567`, opts).some(
        (h) => h.rule.id === 'secret.sentry.dsn'
      )
    ).toBe(false)
  })

  it('rejects DSN missing the project id path', () => {
    expect(
      scanForSecrets(`https://${HEX_32}@sentry.io/`, opts).some(
        (h) => h.rule.id === 'secret.sentry.dsn'
      )
    ).toBe(false)
  })

  it('rejects DSN with uppercase hex in the key (Sentry keys are lowercase)', () => {
    expect(
      scanForSecrets(`https://${'A'.repeat(32)}@o1.ingest.sentry.io/1`, opts).some(
        (h) => h.rule.id === 'secret.sentry.dsn'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — PagerDuty token (labelled)', () => {
  it('matches PAGERDUTY_TOKEN=<20 chars>', () => {
    const text = `PAGERDUTY_TOKEN=${PD_BODY_20}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.pagerduty.tokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(PD_BODY_20)
  })

  it('matches camelCase pagerDutyToken: "<value>"', () => {
    expect(
      scanForSecrets(`{ "pagerDutyToken": "${PD_BODY_20}" }`, opts).some(
        (h) => h.rule.id === 'secret.pagerduty.tokenLabelled'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 20 chars', () => {
    expect(
      scanForSecrets(`PAGERDUTY_TOKEN=${PD_BODY_20.slice(0, 19)}`, opts).some(
        (h) => h.rule.id === 'secret.pagerduty.tokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects body containing characters outside [A-Za-z0-9_+-]', () => {
    expect(
      scanForSecrets(`PAGERDUTY_TOKEN=${'@'.repeat(20)}`, opts).some(
        (h) => h.rule.id === 'secret.pagerduty.tokenLabelled'
      )
    ).toBe(false)
  })

  it('does not flag a bare 20-char identifier without the label', () => {
    expect(
      scanForSecrets(PD_BODY_20, opts).some(
        (h) => h.rule.id === 'secret.pagerduty.tokenLabelled'
      )
    ).toBe(false)
  })
})

describe('OBSERVABILITY_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of OBSERVABILITY_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of OBSERVABILITY_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = OBSERVABILITY_SECRET_RULES.map((r) => r.id).sort()
    expect(ids).toEqual([
      'secret.datadog.apiKeyLabelled',
      'secret.datadog.appKeyLabelled',
      'secret.newRelic.ingestKey',
      'secret.newRelic.licenseKey',
      'secret.newRelic.userKey',
      'secret.pagerduty.tokenLabelled',
      'secret.sentry.dsn',
    ])
  })

  it('every rule carries error severity', () => {
    for (const r of OBSERVABILITY_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })
})
