import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { MISC_SECRET_RULES } from './misc'

const opts = { rules: MISC_SECRET_RULES }

// Mapbox tokens: prefix (pk./sk.) + 60+ base64url + . + 20+ base64url.
// The lookarounds bound the match against the base64url surrounding charset
// so longer alnum runs at either end short-circuit the match.
const MAPBOX_BODY_60 =
  'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUv'
const MAPBOX_TAIL_20 = 'WxYz0123456789_-Wxyz'

// DigitalOcean PAT body: exactly 64 lowercase hex chars.
const DOP_BODY_64 =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

// UUID shape: 8-4-4-4-12 lowercase hex.
const SNYK_UUID = 'a1b2c3d4-e5f6-7890-abcd-ef0123456789'
const HEROKU_UUID = 'fedcba98-7654-3210-fedc-ba9876543210'

// Algolia admin key body: exactly 32 lowercase hex chars.
const ALGOLIA_HEX_32 = '0123456789abcdef0123456789abcdef'

describe('MISC_SECRET_RULES — Mapbox public access token (pk.…)', () => {
  it('matches pk. + 60 base64url + . + 20 base64url', () => {
    const text = `pk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.mapbox.accessToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches longer bodies (>60 / >20 base64url chars)', () => {
    const longerBody = MAPBOX_BODY_60 + 'xyz_-012'
    const longerTail = MAPBOX_TAIL_20 + '01234567'
    expect(
      scanForSecrets(`pk.${longerBody}.${longerTail}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.accessToken'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 60 chars', () => {
    expect(
      scanForSecrets(`pk.${MAPBOX_BODY_60.slice(0, 59)}.${MAPBOX_TAIL_20}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.accessToken'
      )
    ).toBe(false)
  })

  it('rejects tail shorter than 20 chars', () => {
    expect(
      scanForSecrets(`pk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20.slice(0, 19)}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.accessToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer base64url identifier (prefix)', () => {
    expect(
      scanForSecrets(`xpk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.accessToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (sk. is the secret-token rule)', () => {
    expect(
      scanForSecrets(`sk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.accessToken'
      )
    ).toBe(false)
  })

  it('does not trip on short identifiers like `pk.foo`', () => {
    expect(
      scanForSecrets('const pk_foo = 1', opts).some(
        (h) => h.rule.id === 'secret.mapbox.accessToken'
      )
    ).toBe(false)
  })
})

describe('MISC_SECRET_RULES — Mapbox secret access token (sk.…)', () => {
  it('matches sk. + 60 base64url + . + 20 base64url', () => {
    const text = `sk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.mapbox.secretToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 60 chars', () => {
    expect(
      scanForSecrets(`sk.${MAPBOX_BODY_60.slice(0, 59)}.${MAPBOX_TAIL_20}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.secretToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer base64url identifier (prefix)', () => {
    expect(
      scanForSecrets(`xsk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.secretToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (pk. is the public-token rule)', () => {
    expect(
      scanForSecrets(`pk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`, opts).some(
        (h) => h.rule.id === 'secret.mapbox.secretToken'
      )
    ).toBe(false)
  })

  it('confirms severity asymmetry: pk. is info, sk. is error', () => {
    const pkHit = scanForSecrets(
      `pk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`,
      opts
    ).find((h) => h.rule.id === 'secret.mapbox.accessToken')
    const skHit = scanForSecrets(
      `sk.${MAPBOX_BODY_60}.${MAPBOX_TAIL_20}`,
      opts
    ).find((h) => h.rule.id === 'secret.mapbox.secretToken')
    expect(pkHit?.rule.severity).toBe('info')
    expect(skHit?.rule.severity).toBe('error')
  })
})

describe('MISC_SECRET_RULES — Algolia admin key (labelled)', () => {
  it('matches ALGOLIA_ADMIN_KEY=<32 hex> with sensitiveSpan over the value', () => {
    const text = `ALGOLIA_ADMIN_KEY=${ALGOLIA_HEX_32}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(ALGOLIA_HEX_32)
  })

  it('matches ALGOLIA_ADMIN_API_KEY=<32 hex>', () => {
    expect(
      scanForSecrets(`ALGOLIA_ADMIN_API_KEY=${ALGOLIA_HEX_32}`, opts).some(
        (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
      )
    ).toBe(true)
  })

  it('matches JSON-shaped "algoliaAdminKey": "<32 hex>"', () => {
    expect(
      scanForSecrets(`{ "algoliaAdminKey": "${ALGOLIA_HEX_32}" }`, opts).some(
        (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
      )
    ).toBe(true)
  })

  it('rejects body shorter than 32 hex chars', () => {
    expect(
      scanForSecrets(`ALGOLIA_ADMIN_KEY=${ALGOLIA_HEX_32.slice(0, 31)}`, opts).some(
        (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Algolia keys are lowercase)', () => {
    expect(
      scanForSecrets(`ALGOLIA_ADMIN_KEY=${ALGOLIA_HEX_32.toUpperCase()}`, opts).some(
        (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
      )
    ).toBe(false)
  })

  it('does not flag a bare 32-hex run without the label', () => {
    expect(
      scanForSecrets(ALGOLIA_HEX_32, opts).some(
        (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects label mismatch (ALGOLIA_SEARCH_KEY=…)', () => {
    expect(
      scanForSecrets(`ALGOLIA_SEARCH_KEY=${ALGOLIA_HEX_32}`, opts).some(
        (h) => h.rule.id === 'secret.algolia.adminKeyLabelled'
      )
    ).toBe(false)
  })
})

describe('MISC_SECRET_RULES — DigitalOcean personal access token (dop_v1_…)', () => {
  it('matches dop_v1_ + 64 lowercase hex', () => {
    const text = `dop_v1_${DOP_BODY_64}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('rejects body shorter than 64 hex chars', () => {
    expect(
      scanForSecrets(`dop_v1_${DOP_BODY_64.slice(0, 63)}`, opts).some(
        (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
      )
    ).toBe(false)
  })

  it('rejects body longer than 64 hex chars (trailing alnum breaks the boundary)', () => {
    expect(
      scanForSecrets(`dop_v1_${DOP_BODY_64}a`, opts).some(
        (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (DigitalOcean tokens are lowercase)', () => {
    expect(
      scanForSecrets(`dop_v1_${DOP_BODY_64.toUpperCase()}`, opts).some(
        (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
      )
    ).toBe(false)
  })

  it('rejects token embedded in a longer identifier (alnum prefix)', () => {
    expect(
      scanForSecrets(`xdop_v1_${DOP_BODY_64}`, opts).some(
        (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
      )
    ).toBe(false)
  })

  it('rejects token with leading underscore (identifier-context)', () => {
    expect(
      scanForSecrets(`x_dop_v1_${DOP_BODY_64}`, opts).some(
        (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
      )
    ).toBe(false)
  })

  it('rejects prefix mismatch (dop_v2_ instead of dop_v1_)', () => {
    expect(
      scanForSecrets(`dop_v2_${DOP_BODY_64}`, opts).some(
        (h) => h.rule.id === 'secret.digitalocean.personalAccessToken'
      )
    ).toBe(false)
  })
})

describe('MISC_SECRET_RULES — Snyk token (labelled)', () => {
  it('matches SNYK_TOKEN=<uuid> with sensitiveSpan over the UUID', () => {
    const text = `SNYK_TOKEN=${SNYK_UUID}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.snyk.tokenLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(SNYK_UUID)
  })

  it('matches SNYK_API_TOKEN=<uuid>', () => {
    expect(
      scanForSecrets(`SNYK_API_TOKEN=${SNYK_UUID}`, opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(true)
  })

  it('matches JSON-shaped "snykToken": "<uuid>"', () => {
    expect(
      scanForSecrets(`{ "snykToken": "${SNYK_UUID}" }`, opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(true)
  })

  it('rejects malformed UUID (missing hyphen segments)', () => {
    expect(
      scanForSecrets(`SNYK_TOKEN=${SNYK_UUID.replace(/-/g, '')}`, opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Snyk UUIDs are lowercase)', () => {
    expect(
      scanForSecrets(`SNYK_TOKEN=${SNYK_UUID.toUpperCase()}`, opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(false)
  })

  it('does not flag a bare UUID without the label', () => {
    expect(
      scanForSecrets(SNYK_UUID, opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects label mismatch (SNYK_KEY=…)', () => {
    expect(
      scanForSecrets(`SNYK_KEY=${SNYK_UUID}`, opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(false)
  })

  it('rejects empty value `SNYK_TOKEN=`', () => {
    expect(
      scanForSecrets('SNYK_TOKEN=', opts).some(
        (h) => h.rule.id === 'secret.snyk.tokenLabelled'
      )
    ).toBe(false)
  })
})

describe('MISC_SECRET_RULES — Heroku API key (labelled)', () => {
  it('matches HEROKU_API_KEY=<uuid> with sensitiveSpan over the UUID', () => {
    const text = `HEROKU_API_KEY=${HEROKU_UUID}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEROKU_UUID)
  })

  it('matches HEROKU_AUTH_TOKEN=<uuid> (.netrc form)', () => {
    expect(
      scanForSecrets(`HEROKU_AUTH_TOKEN=${HEROKU_UUID}`, opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(true)
  })

  it('matches JSON-shaped "herokuApiKey": "<uuid>"', () => {
    expect(
      scanForSecrets(`{ "herokuApiKey": "${HEROKU_UUID}" }`, opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(true)
  })

  it('rejects malformed UUID (missing hyphen segments)', () => {
    expect(
      scanForSecrets(`HEROKU_API_KEY=${HEROKU_UUID.replace(/-/g, '')}`, opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects uppercase hex (Heroku UUIDs are lowercase)', () => {
    expect(
      scanForSecrets(`HEROKU_API_KEY=${HEROKU_UUID.toUpperCase()}`, opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(false)
  })

  it('does not flag a bare UUID without the label', () => {
    expect(
      scanForSecrets(HEROKU_UUID, opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects label mismatch (HEROKU_APP=…)', () => {
    expect(
      scanForSecrets(`HEROKU_APP=${HEROKU_UUID}`, opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(false)
  })

  it('rejects empty value `HEROKU_API_KEY=`', () => {
    expect(
      scanForSecrets('HEROKU_API_KEY=', opts).some(
        (h) => h.rule.id === 'secret.heroku.apiKeyLabelled'
      )
    ).toBe(false)
  })
})

describe('MISC_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of MISC_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.<vendor>', () => {
    for (const r of MISC_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('Mapbox pk. is info, every other rule is error', () => {
    for (const r of MISC_SECRET_RULES) {
      if (r.id === 'secret.mapbox.accessToken') {
        expect(r.severity).toBe('info')
      } else {
        expect(r.severity).toBe('error')
      }
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = MISC_SECRET_RULES.map((r) => r.id).sort()
    expect(ids).toEqual([
      'secret.algolia.adminKeyLabelled',
      'secret.digitalocean.personalAccessToken',
      'secret.heroku.apiKeyLabelled',
      'secret.mapbox.accessToken',
      'secret.mapbox.secretToken',
      'secret.snyk.tokenLabelled',
    ])
  })

  it('labelled rules expose a sensitiveSpan helper', () => {
    const labelled = MISC_SECRET_RULES.filter(
      (r) =>
        r.id === 'secret.algolia.adminKeyLabelled' ||
        r.id === 'secret.snyk.tokenLabelled' ||
        r.id === 'secret.heroku.apiKeyLabelled'
    )
    expect(labelled.length).toBe(3)
    for (const r of labelled) {
      expect(typeof r.sensitiveSpan).toBe('function')
    }
  })

  it('sensitiveSpan falls back to whole-raw range if regex misses', () => {
    // Exercise the helper's fallback branch — non-matching raw inputs return
    // the full-length span. This guards the `if (!m) return …` branch in the
    // shared helper.
    const algolia = MISC_SECRET_RULES.find(
      (r) => r.id === 'secret.algolia.adminKeyLabelled'
    )!
    const snyk = MISC_SECRET_RULES.find((r) => r.id === 'secret.snyk.tokenLabelled')!
    const heroku = MISC_SECRET_RULES.find(
      (r) => r.id === 'secret.heroku.apiKeyLabelled'
    )!
    expect(algolia.sensitiveSpan!('not-a-real-match')).toEqual({
      start: 0,
      end: 'not-a-real-match'.length,
    })
    expect(snyk.sensitiveSpan!('not-a-real-match')).toEqual({
      start: 0,
      end: 'not-a-real-match'.length,
    })
    expect(heroku.sensitiveSpan!('not-a-real-match')).toEqual({
      start: 0,
      end: 'not-a-real-match'.length,
    })
  })
})
