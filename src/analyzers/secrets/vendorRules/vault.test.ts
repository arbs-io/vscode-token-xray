import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { VAULT_SECRET_RULES } from './vault'

const opts = { rules: VAULT_SECRET_RULES }

// 24-char base64url-ish body for `hvs.` / `hvr.` tokens.
const BODY_24 = 'A'.repeat(12) + 'a'.repeat(6) + '012345' // 24
const BODY_24_DASHED = 'A'.repeat(10) + '_-' + 'b'.repeat(8) + '012345' // 26 incl. _-, exceeds 24
// Terraform Cloud user-id segment is exactly 14 alnum.
const TFC_USER = 'A'.repeat(7) + 'a'.repeat(4) + '012' // 14
const TFC_BODY_60 = 'A'.repeat(30) + 'b'.repeat(20) + '0123456789' // 60

describe('VAULT_SECRET_RULES — Vault service token', () => {
  it('matches hvs.<24+ chars>', () => {
    const text = `hvs.${BODY_24}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.vault.serviceToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(`hvs.${BODY_24}`)
  })

  it('matches hvs. body containing underscores / dashes', () => {
    const text = `hvs.${BODY_24_DASHED}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.serviceToken')
    ).toBe(true)
  })

  it('rejects hvs. with body shorter than 24 chars', () => {
    const text = 'hvs.' + 'a'.repeat(23)
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.serviceToken')
    ).toBe(false)
  })

  it('rejects identifier prefixed by alnum (e.g. `myhvs.<body>`)', () => {
    const text = `myhvs.${BODY_24}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.serviceToken')
    ).toBe(false)
  })

  it('rejects identifier prefixed by `_` / `-`', () => {
    const text = `_hvs.${BODY_24}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.serviceToken')
    ).toBe(false)
  })
})

describe('VAULT_SECRET_RULES — Vault root token', () => {
  it('matches hvr.<24+ alnum>', () => {
    const text = `hvr.${BODY_24}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.vault.rootToken')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(`hvr.${BODY_24}`)
  })

  it('rejects hvr. with body shorter than 24 chars', () => {
    const text = 'hvr.' + 'a'.repeat(23)
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.rootToken')
    ).toBe(false)
  })

  it('rejects identifier `foohvr.<body>` (alnum prefix)', () => {
    const text = `foohvr.${BODY_24}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.rootToken')
    ).toBe(false)
  })

  it('rejects hvr. body containing underscores (root tokens are alnum only)', () => {
    // hvr. permits only [A-Za-z0-9], so an underscore inside the first 24
    // chars should *not* qualify as a root token.
    const text = 'hvr.' + 'a'.repeat(10) + '_' + 'b'.repeat(13)
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.rootToken')
    ).toBe(false)
  })
})

describe('VAULT_SECRET_RULES — VAULT_TOKEN labelled', () => {
  it('matches VAULT_TOKEN=<value> with sensitiveSpan over the value', () => {
    const value = `hvs.${BODY_24}`
    const text = `VAULT_TOKEN=${value}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.vault.labelled')
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(value)
  })

  it('matches quoted JSON VAULT_TOKEN style', () => {
    const value = `hvs.${BODY_24}`
    const text = `{"VAULT_TOKEN": "${value}"}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.vault.labelled')
    ).toBe(true)
  })

  it('rejects empty value `VAULT_TOKEN=`', () => {
    expect(
      scanForSecrets('VAULT_TOKEN=', opts).some((h) => h.rule.id === 'secret.vault.labelled')
    ).toBe(false)
  })

  it('rejects too-short value', () => {
    expect(
      scanForSecrets('VAULT_TOKEN=short', opts).some((h) => h.rule.id === 'secret.vault.labelled')
    ).toBe(false)
  })
})

describe('VAULT_SECRET_RULES — Terraform Cloud user token', () => {
  it('matches <14 alnum>.atlasv1.<60+ chars>', () => {
    const text = `${TFC_USER}.atlasv1.${TFC_BODY_60}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.terraformCloud.userToken'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(text)
  })

  it('matches body containing underscores / dashes', () => {
    const body = 'A'.repeat(30) + '_-' + 'b'.repeat(28) // 60 incl. _-
    const text = `${TFC_USER}.atlasv1.${body}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.terraformCloud.userToken')
    ).toBe(true)
  })

  it('rejects body shorter than 60 chars', () => {
    const text = `${TFC_USER}.atlasv1.${'a'.repeat(40)}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.terraformCloud.userToken')
    ).toBe(false)
  })

  it('rejects user-id segment not exactly 14 alnum', () => {
    const text = `${'A'.repeat(10)}.atlasv1.${TFC_BODY_60}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.terraformCloud.userToken')
    ).toBe(false)
  })
})

describe('VAULT_SECRET_RULES — TF_TOKEN_app_terraform_io labelled', () => {
  it('matches TF_TOKEN_app_terraform_io=<value>', () => {
    const value = `${TFC_USER}.atlasv1.${TFC_BODY_60}`
    const text = `TF_TOKEN_app_terraform_io=${value}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.terraformCloud.labelled'
    )
    expect(hit).toBeDefined()
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(value)
  })

  it('matches quoted JSON form', () => {
    const value = `${TFC_USER}.atlasv1.${TFC_BODY_60}`
    const text = `{"TF_TOKEN_app_terraform_io": "${value}"}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.terraformCloud.labelled')
    ).toBe(true)
  })

  it('rejects empty value `TF_TOKEN_app_terraform_io=`', () => {
    expect(
      scanForSecrets('TF_TOKEN_app_terraform_io=', opts).some(
        (h) => h.rule.id === 'secret.terraformCloud.labelled'
      )
    ).toBe(false)
  })

  it('rejects too-short value', () => {
    expect(
      scanForSecrets('TF_TOKEN_app_terraform_io=short', opts).some(
        (h) => h.rule.id === 'secret.terraformCloud.labelled'
      )
    ).toBe(false)
  })
})

describe('VAULT_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of VAULT_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.', () => {
    for (const r of VAULT_SECRET_RULES) {
      expect(r.id.startsWith('secret.')).toBe(true)
      // shape: secret.<vendor>.<reason>
      expect(r.id.split('.').length).toBeGreaterThanOrEqual(3)
    }
  })

  it('all rules carry error severity', () => {
    for (const r of VAULT_SECRET_RULES) {
      expect(r.severity).toBe('error')
    }
  })

  it('exposes the expected rule ids', () => {
    const ids = VAULT_SECRET_RULES.map((r) => r.id).sort()
    expect(ids).toEqual([
      'secret.terraformCloud.labelled',
      'secret.terraformCloud.userToken',
      'secret.vault.labelled',
      'secret.vault.rootToken',
      'secret.vault.serviceToken',
    ])
  })
})
