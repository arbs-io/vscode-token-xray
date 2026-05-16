import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { GITHUB_SECRET_RULES } from './github'

const opts = { rules: GITHUB_SECRET_RULES }
const HEX40 = 'a'.repeat(40)

describe('GITHUB_SECRET_RULES — App / OAuth App client_secret', () => {
  it('matches GITHUB_CLIENT_SECRET= 40 hex', () => {
    const text = `GITHUB_CLIENT_SECRET=${HEX40}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.github.appClientSecret'
    )
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(HEX40)
  })

  it('matches GH_CLIENT_SECRET alias', () => {
    expect(
      scanForSecrets(`GH_CLIENT_SECRET="${HEX40}"`, opts).some(
        (h) => h.rule.id === 'secret.github.appClientSecret'
      )
    ).toBe(true)
  })

  it('matches camelCase githubClientSecret', () => {
    expect(
      scanForSecrets(`{"githubClientSecret":"${HEX40}"}`, opts).some(
        (h) => h.rule.id === 'secret.github.appClientSecret'
      )
    ).toBe(true)
  })

  it('rejects non-hex / wrong-length values', () => {
    expect(scanForSecrets('GITHUB_CLIENT_SECRET=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', opts)).toEqual([])
    expect(scanForSecrets(`GITHUB_CLIENT_SECRET=${'a'.repeat(39)}`, opts)).toEqual([])
  })
})

describe('GITHUB_SECRET_RULES — webhook secret', () => {
  it('matches GITHUB_WEBHOOK_SECRET= 16+ chars', () => {
    const text = 'GITHUB_WEBHOOK_SECRET=my-super-secret-webhook-key'
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.github.webhookSecret')
    expect(hit?.rule.severity).toBe('error')
  })

  it('rejects too-short values', () => {
    expect(scanForSecrets('GITHUB_WEBHOOK_SECRET=short', opts)).toEqual([])
  })
})

describe('GITHUB_SECRET_RULES — App private key path', () => {
  it('matches GITHUB_APP_PRIVATE_KEY_PATH= unix path to .pem', () => {
    const text = 'GITHUB_APP_PRIVATE_KEY_PATH=/etc/secrets/github-app.private.pem'
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.github.appPrivateKeyPath'
    )
    expect(hit?.rule.severity).toBe('info')
  })

  it('matches Windows path to .pem', () => {
    const text = String.raw`GITHUB_APP_PRIVATE_KEY_PATH="C:\secrets\app.pem"`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.github.appPrivateKeyPath')
    ).toBe(true)
  })

  it('rejects non-.pem paths', () => {
    expect(scanForSecrets('GITHUB_APP_PRIVATE_KEY_PATH=/etc/secrets/app.txt', opts)).toEqual([])
  })
})

describe('GITHUB_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of GITHUB_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.github', () => {
    for (const r of GITHUB_SECRET_RULES) {
      expect(r.id.startsWith('secret.github.')).toBe(true)
    }
  })
})
