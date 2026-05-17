import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeOidcDiscovery } from './decoder'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

describe('decodeOidcDiscovery', () => {
  it('decodes a healthy discovery document', () => {
    const decoded = decodeOidcDiscovery(read('healthy.json'))
    expect(decoded).toBeDefined()
    if (!decoded) throw new Error('expected defined')
    expect(decoded.issuer).toBe('https://idp.example.com/issuer')
    expect(decoded.jwksUri).toBe('https://idp.example.com/oauth2/jwks')
    expect(decoded.authorizationEndpoint).toBe('https://idp.example.com/oauth2/authorize')
    expect(decoded.tokenEndpoint).toBe('https://idp.example.com/oauth2/token')
    expect(decoded.userinfoEndpoint).toBe('https://idp.example.com/oauth2/userinfo')
    expect(decoded.idTokenSigningAlgValuesSupported).toEqual(['RS256', 'ES256'])
    expect(decoded.scopesSupported).toEqual(['openid', 'profile', 'email', 'offline_access'])
    expect(decoded.responseTypesSupported).toEqual(['code', 'id_token', 'code id_token'])
    expect(decoded.raw).toEqual(JSON.parse(read('healthy.json')))
  })

  it('decodes a config without optional endpoints', () => {
    const minimal = JSON.stringify({
      issuer: 'https://idp/x',
      authorization_endpoint: 'https://idp/x/auth',
      jwks_uri: 'https://idp/x/jwks',
    })
    const decoded = decodeOidcDiscovery(minimal)
    expect(decoded).toBeDefined()
    if (!decoded) throw new Error('expected defined')
    expect(decoded.tokenEndpoint).toBeUndefined()
    expect(decoded.userinfoEndpoint).toBeUndefined()
    expect(decoded.idTokenSigningAlgValuesSupported).toBeUndefined()
    expect(decoded.scopesSupported).toBeUndefined()
    expect(decoded.responseTypesSupported).toBeUndefined()
  })

  it('returns undefined for non-JSON input', () => {
    expect(decodeOidcDiscovery('hello world')).toBeUndefined()
    expect(decodeOidcDiscovery('')).toBeUndefined()
    expect(decodeOidcDiscovery('   ')).toBeUndefined()
  })

  it('returns undefined for malformed JSON', () => {
    expect(decodeOidcDiscovery('{not valid json')).toBeUndefined()
  })

  it('returns undefined for JSON arrays / primitives', () => {
    expect(decodeOidcDiscovery('[]')).toBeUndefined()
    expect(decodeOidcDiscovery('null')).toBeUndefined()
    expect(decodeOidcDiscovery('123')).toBeUndefined()
  })

  it('returns undefined when issuer is missing', () => {
    const json = JSON.stringify({
      authorization_endpoint: 'https://idp/auth',
      jwks_uri: 'https://idp/jwks',
    })
    expect(decodeOidcDiscovery(json)).toBeUndefined()
  })

  it('returns undefined when jwks_uri is missing', () => {
    const json = JSON.stringify({
      issuer: 'https://idp',
      authorization_endpoint: 'https://idp/auth',
    })
    expect(decodeOidcDiscovery(json)).toBeUndefined()
  })

  it('returns undefined when authorization_endpoint is missing', () => {
    const json = JSON.stringify({
      issuer: 'https://idp',
      jwks_uri: 'https://idp/jwks',
    })
    expect(decodeOidcDiscovery(json)).toBeUndefined()
  })

  it('returns undefined when required fields are not strings', () => {
    const json = JSON.stringify({ issuer: 1, jwks_uri: true, authorization_endpoint: null })
    expect(decodeOidcDiscovery(json)).toBeUndefined()
  })

  it('returns undefined when required fields are empty strings', () => {
    const json = JSON.stringify({ issuer: '', jwks_uri: '', authorization_endpoint: '' })
    expect(decodeOidcDiscovery(json)).toBeUndefined()
  })

  it('ignores non-string entries in array fields', () => {
    const json = JSON.stringify({
      issuer: 'https://idp',
      jwks_uri: 'https://idp/jwks',
      authorization_endpoint: 'https://idp/auth',
      id_token_signing_alg_values_supported: ['RS256', 1, null, 'ES256'],
    })
    const decoded = decodeOidcDiscovery(json)
    expect(decoded?.idTokenSigningAlgValuesSupported).toEqual(['RS256', 'ES256'])
  })

  it('drops empty array fields entirely', () => {
    const json = JSON.stringify({
      issuer: 'https://idp',
      jwks_uri: 'https://idp/jwks',
      authorization_endpoint: 'https://idp/auth',
      id_token_signing_alg_values_supported: [],
      scopes_supported: [1, 2, 3],
    })
    const decoded = decodeOidcDiscovery(json)
    expect(decoded?.idTokenSigningAlgValuesSupported).toBeUndefined()
    expect(decoded?.scopesSupported).toBeUndefined()
  })

  it('accepts whitespace-prefixed JSON', () => {
    const json = '   \n\t' + JSON.stringify({
      issuer: 'https://idp',
      jwks_uri: 'https://idp/jwks',
      authorization_endpoint: 'https://idp/auth',
    })
    expect(decodeOidcDiscovery(json)).toBeDefined()
  })

  it('rejects non-string input', () => {
    expect(decodeOidcDiscovery(undefined as unknown as string)).toBeUndefined()
    expect(decodeOidcDiscovery(null as unknown as string)).toBeUndefined()
  })

  it('rejects JSON that does not start with `{`', () => {
    expect(decodeOidcDiscovery('"some string"')).toBeUndefined()
  })
})
