import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { PRODUCTIVITY_SECRET_RULES } from './productivity'

const opts = { rules: PRODUCTIVITY_SECRET_RULES }

// Notion integration token body: exactly 43 alnum characters.
const NOTION_BODY_43 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG'

// Linear API key body: exactly 40 alnum characters.
const LINEAR_API_BODY_40 = 'AbCdEfGhIjKlMnOpQrStUvWxYz01234567890ABC'

// Linear OAuth body: 40+ alnum characters (rule accepts {40,}).
const LINEAR_OAUTH_BODY_40 = 'aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStT'

// Figma PAT body: 40+ base64url-ish characters (rule accepts {40,}).
const FIGMA_BODY_40 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Ab'

// Postman API key segments: exactly 24 lowercase hex + 34 lowercase hex.
const PMAK_HEX_24 = 'a1b2c3d4e5f6a7b8c9d0e1f2'
const PMAK_HEX_34 = '0123456789abcdef0123456789abcdef00'

// Labelled-value placeholder (>=16 chars).
const LABELLED_VALUE_16 = 'A'.repeat(8) + 'b'.repeat(4) + '0123'

describe('PRODUCTIVITY_SECRET_RULES — Notion integration token (secret_…)', () => {
  it('matches secret_ + 43 alnum chars', () => {
    const text = `secret_${NOTION_BODY_43}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.notion.integrationToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 43 chars', () => {
    expect(
      scanForSecrets(`secret_${NOTION_BODY_43.slice(0, 42)}`, opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
  })

  it('rejects body longer than 43 alnum chars (trailing alnum breaks the boundary)', () => {
    expect(
      scanForSecrets(`secret_${NOTION_BODY_43}X`, opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_` or `-`)', () => {
    expect(
      scanForSecrets(`secret_${'_'.repeat(43)}`, opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
    expect(
      scanForSecrets(`secret_${'-'.repeat(43)}`, opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
  })

  it('does not trip on short identifiers like `secret_foo`', () => {
    expect(
      scanForSecrets('const secret_foo = 1', opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xsecret_${NOTION_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`my_secret_${NOTION_BODY_43}`, opts).some(
        (h) => h.rule.id === 'secret.notion.integrationToken'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — Linear API key (lin_api_…)', () => {
  it('matches lin_api_ + 40 alnum chars', () => {
    const text = `lin_api_${LINEAR_API_BODY_40}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.linear.apiKey')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 40 chars', () => {
    expect(
      scanForSecrets(`lin_api_${LINEAR_API_BODY_40.slice(0, 39)}`, opts).some(
        (h) => h.rule.id === 'secret.linear.apiKey'
      )
    ).toBe(false)
  })

  it('rejects body longer than exactly 40 alnum chars (trailing alnum breaks boundary)', () => {
    expect(
      scanForSecrets(`lin_api_${LINEAR_API_BODY_40}X`, opts).some(
        (h) => h.rule.id === 'secret.linear.apiKey'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_`)', () => {
    expect(
      scanForSecrets(`lin_api_${'_'.repeat(40)}`, opts).some(
        (h) => h.rule.id === 'secret.linear.apiKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xlin_api_${LINEAR_API_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.linear.apiKey'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (lin_oauth_ — different Linear rule)', () => {
    expect(
      scanForSecrets(`lin_oapi_${LINEAR_API_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.linear.apiKey'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — Linear OAuth token (lin_oauth_…)', () => {
  it('matches lin_oauth_ + 40 alnum chars', () => {
    const text = `lin_oauth_${LINEAR_OAUTH_BODY_40}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.linear.oauthToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches longer bodies (>40 alnum chars)', () => {
    const longerBody = LINEAR_OAUTH_BODY_40 + 'ABCDEFGH'
    expect(
      scanForSecrets(`lin_oauth_${longerBody}`, opts).some(
        (h) => h.rule.id === 'secret.linear.oauthToken'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 40 chars', () => {
    expect(
      scanForSecrets(`lin_oauth_${LINEAR_OAUTH_BODY_40.slice(0, 39)}`, opts).some(
        (h) => h.rule.id === 'secret.linear.oauthToken'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9] (e.g. `_`)', () => {
    expect(
      scanForSecrets(`lin_oauth_${'_'.repeat(40)}`, opts).some(
        (h) => h.rule.id === 'secret.linear.oauthToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xlin_oauth_${LINEAR_OAUTH_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.linear.oauthToken'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — Figma personal access token (figd_…)', () => {
  it('matches figd_ + 40 base64url chars', () => {
    const text = `figd_${FIGMA_BODY_40}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.figma.pat')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches longer bodies (>40 base64url chars)', () => {
    const longerBody = FIGMA_BODY_40 + 'xyz_-012'
    expect(
      scanForSecrets(`figd_${longerBody}`, opts).some((h) => h.rule.id === 'secret.figma.pat')
    ).toBe(true)
  })

  it('rejects body shorter than 40 chars', () => {
    expect(
      scanForSecrets(`figd_${FIGMA_BODY_40.slice(0, 39)}`, opts).some(
        (h) => h.rule.id === 'secret.figma.pat'
      )
    ).toBe(false)
  })

  it('rejects body chars outside [A-Za-z0-9_-] (e.g. `@`)', () => {
    expect(
      scanForSecrets(`figd_${'@'.repeat(40)}`, opts).some(
        (h) => h.rule.id === 'secret.figma.pat'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer base64url identifier', () => {
    expect(
      scanForSecrets(`xfigd_${FIGMA_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.figma.pat'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_figd_${FIGMA_BODY_40}`, opts).some(
        (h) => h.rule.id === 'secret.figma.pat'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — Postman API key (PMAK-…)', () => {
  it('matches PMAK-<24 hex>-<34 hex>', () => {
    const text = `PMAK-${PMAK_HEX_24}-${PMAK_HEX_34}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.postman.apiKey')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects first segment shorter than 24 hex chars', () => {
    expect(
      scanForSecrets(`PMAK-${PMAK_HEX_24.slice(0, 23)}-${PMAK_HEX_34}`, opts).some(
        (h) => h.rule.id === 'secret.postman.apiKey'
      )
    ).toBe(false)
  })

  it('rejects second segment shorter than 34 hex chars', () => {
    expect(
      scanForSecrets(`PMAK-${PMAK_HEX_24}-${PMAK_HEX_34.slice(0, 33)}`, opts).some(
        (h) => h.rule.id === 'secret.postman.apiKey'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Postman keys are lowercase)', () => {
    expect(
      scanForSecrets(`PMAK-${PMAK_HEX_24.toUpperCase()}-${PMAK_HEX_34}`, opts).some(
        (h) => h.rule.id === 'secret.postman.apiKey'
      )
    ).toBe(false)
  })

  it('rejects non-hex body chars (e.g. `g`)', () => {
    expect(
      scanForSecrets(`PMAK-${'g'.repeat(24)}-${PMAK_HEX_34}`, opts).some(
        (h) => h.rule.id === 'secret.postman.apiKey'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (PMAX-)', () => {
    expect(
      scanForSecrets(`PMAX-${PMAK_HEX_24}-${PMAK_HEX_34}`, opts).some(
        (h) => h.rule.id === 'secret.postman.apiKey'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xPMAK-${PMAK_HEX_24}-${PMAK_HEX_34}`, opts).some(
        (h) => h.rule.id === 'secret.postman.apiKey'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — Asana PAT labelled', () => {
  it('matches ASANA_PAT=<value> with sensitiveSpan over the value', () => {
    const text = `ASANA_PAT=${LABELLED_VALUE_16}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.asana.patLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(LABELLED_VALUE_16)
  })

  it('matches ASANA_TOKEN=<value>', () => {
    expect(
      scanForSecrets(`ASANA_TOKEN=${LABELLED_VALUE_16}`, opts).some(
        (h) => h.rule.id === 'secret.asana.patLabelled'
      )
    ).toBe(true)
  })

  it('matches quoted JSON `"asanaToken": "<value>"`', () => {
    const text = `{"asanaToken": "${LABELLED_VALUE_16}"}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.asana.patLabelled')
    ).toBe(true)
  })

  it('rejects empty value `ASANA_PAT=`', () => {
    expect(
      scanForSecrets('ASANA_PAT=', opts).some(
        (h) => h.rule.id === 'secret.asana.patLabelled'
      )
    ).toBe(false)
  })

  it('rejects a too-short value (under 16 chars)', () => {
    expect(
      scanForSecrets('ASANA_PAT=short', opts).some(
        (h) => h.rule.id === 'secret.asana.patLabelled'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — Monday.com token labelled', () => {
  it('matches MONDAY_API_TOKEN=<value> with sensitiveSpan over the value', () => {
    const text = `MONDAY_API_TOKEN=${LABELLED_VALUE_16}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.monday.tokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(LABELLED_VALUE_16)
  })

  it('matches MONDAY_TOKEN=<value>', () => {
    expect(
      scanForSecrets(`MONDAY_TOKEN=${LABELLED_VALUE_16}`, opts).some(
        (h) => h.rule.id === 'secret.monday.tokenLabelled'
      )
    ).toBe(true)
  })

  it('matches quoted JSON `"mondayApiToken": "<value>"`', () => {
    const text = `{"mondayApiToken": "${LABELLED_VALUE_16}"}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.monday.tokenLabelled')
    ).toBe(true)
  })

  it('rejects empty value `MONDAY_API_TOKEN=`', () => {
    expect(
      scanForSecrets('MONDAY_API_TOKEN=', opts).some(
        (h) => h.rule.id === 'secret.monday.tokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects a too-short value (under 16 chars)', () => {
    expect(
      scanForSecrets('MONDAY_API_TOKEN=short', opts).some(
        (h) => h.rule.id === 'secret.monday.tokenLabelled'
      )
    ).toBe(false)
  })
})

describe('PRODUCTIVITY_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of PRODUCTIVITY_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of PRODUCTIVITY_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('all rules carry error severity', () => {
    for (const r of PRODUCTIVITY_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = PRODUCTIVITY_SECRET_RULES.map((r) => r.id).sort((a, b) => a.localeCompare(b))
    expect(ids).toEqual([
      'secret.asana.patLabelled',
      'secret.figma.pat',
      'secret.linear.apiKey',
      'secret.linear.oauthToken',
      'secret.monday.tokenLabelled',
      'secret.notion.integrationToken',
      'secret.postman.apiKey',
    ])
  })

  it('labelled rules expose a sensitiveSpan helper', () => {
    const labelled = PRODUCTIVITY_SECRET_RULES.filter(
      (r) => r.id === 'secret.asana.patLabelled' || r.id === 'secret.monday.tokenLabelled'
    )
    expect(labelled.length).toBe(2)
    for (const r of labelled) {
      expect(typeof r.sensitiveSpan).toBe('function')
    }
  })
})
