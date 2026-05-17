import { describe, expect, it } from 'vitest'
import { scanForSecrets } from '../scanner'
import { AZURE_SECRET_RULES } from './azure'

const opts = { rules: AZURE_SECRET_RULES }
const KEY_88 = 'A'.repeat(88) // typical Azure storage key length when base64-decoded to 64 bytes
const KEY_44 = 'B'.repeat(44) // typical Service Bus key
const UUID = '11111111-2222-3333-4444-555555555555'

describe('AZURE_SECRET_RULES — storage AccountKey', () => {
  it('matches AccountKey= in a connection string', () => {
    const text = `DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=${KEY_88};EndpointSuffix=core.windows.net`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.azure.accountKey')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(KEY_88)
  })

  it('rejects too-short keys', () => {
    expect(scanForSecrets('AccountKey=short', opts)).toEqual([])
  })
})

describe('AZURE_SECRET_RULES — SharedAccessKey', () => {
  it('matches SharedAccessKey= in a Service Bus connection string', () => {
    const text = `Endpoint=sb://demo.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=${KEY_44};EntityPath=demo`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.azure.sharedAccessKey'
    )
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(KEY_44)
  })

  it('rejects too-short keys', () => {
    expect(scanForSecrets('SharedAccessKey=short', opts)).toEqual([])
  })
})

describe('AZURE_SECRET_RULES — SAS token', () => {
  it('matches an Azure storage SAS query string (sv + sig + extras)', () => {
    const sas =
      'sv=2024-08-04&ss=b&srt=sco&sp=rwdlacx&se=2027-01-01T00:00:00Z&st=2024-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjK%2FlMnOpQrStUvWxYz0123456789'
    const text = `https://demo.blob.core.windows.net/container/blob?${sas}`
    expect(
      scanForSecrets(text, opts).some((h) => h.rule.id === 'secret.azure.sasToken')
    ).toBe(true)
  })

  it('does not match arbitrary query strings without sv+sig', () => {
    expect(scanForSecrets('https://example.com?foo=bar&baz=qux', opts)).toEqual([])
  })

  it('does not match sig= without sv=', () => {
    expect(scanForSecrets('https://example.com?sig=abc', opts)).toEqual([])
  })
})

describe('AZURE_SECRET_RULES — client_secret', () => {
  const FIXTURE_40 = 'aA1~bB2.cC3_dD4-eE5fF6gG7hH8iI9jJ0kK1lL2mM'

  it('matches AZURE_CLIENT_SECRET=...', () => {
    const text = `AZURE_CLIENT_SECRET=${FIXTURE_40}`
    const hit = scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.azure.clientSecret')
    expect(hit?.rule.severity).toBe('error')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(FIXTURE_40)
  })

  it('matches ARM_CLIENT_SECRET alias', () => {
    expect(
      scanForSecrets(`ARM_CLIENT_SECRET="${FIXTURE_40}"`, opts).some(
        (h) => h.rule.id === 'secret.azure.clientSecret'
      )
    ).toBe(true)
  })

  it('rejects too-short values', () => {
    expect(scanForSecrets('AZURE_CLIENT_SECRET=short', opts)).toEqual([])
  })
})

describe('AZURE_SECRET_RULES — subscription / tenant ID', () => {
  it('matches AZURE_SUBSCRIPTION_ID=<uuid> as info', () => {
    const text = `AZURE_SUBSCRIPTION_ID=${UUID}`
    const hit = scanForSecrets(text, opts).find(
      (h) => h.rule.id === 'secret.azure.subscriptionId'
    )
    expect(hit?.rule.severity).toBe('info')
    expect(text.slice(hit!.sensitiveStart, hit!.sensitiveEnd)).toBe(UUID)
  })

  it('matches AZURE_TENANT_ID=<uuid> as info', () => {
    const text = `AZURE_TENANT_ID=${UUID}`
    expect(
      scanForSecrets(text, opts).find((h) => h.rule.id === 'secret.azure.tenantId')?.rule.severity
    ).toBe('info')
  })

  it('rejects malformed UUIDs', () => {
    expect(scanForSecrets('AZURE_TENANT_ID=not-a-uuid', opts)).toEqual([])
  })
})

describe('AZURE_SECRET_RULES — coverage', () => {
  it('all rules use the global flag', () => {
    for (const r of AZURE_SECRET_RULES) {
      expect(r.pattern.flags).toContain('g')
    }
  })

  it('all rules are namespaced under secret.azure', () => {
    for (const r of AZURE_SECRET_RULES) {
      expect(r.id.startsWith('secret.azure.')).toBe(true)
    }
  })
})
