import { describe, expect, it } from 'vitest'
import { createDefaultRegistry } from './defaultRegistry'

describe('createDefaultRegistry', () => {
  it('registers all built-in analyzers', () => {
    const reg = createDefaultRegistry()
    const ids = reg.list().map((a) => a.id).sort()
    expect(ids).toEqual(['awsSigv4', 'basicAuth', 'cookie', 'jwk', 'jwt', 'oauth', 'paseto', 'saml', 'secret', 'x509'])
  })

  it('exposes analyzers by id', () => {
    const reg = createDefaultRegistry()
    expect(reg.get('jwt')?.id).toBe('jwt')
    expect(reg.get('saml')?.id).toBe('saml')
    expect(reg.get('x509')?.id).toBe('x509')
    expect(reg.get('jwk')?.id).toBe('jwk')
    expect(reg.get('oauth')?.id).toBe('oauth')
    expect(reg.get('cookie')?.id).toBe('cookie')
    expect(reg.get('paseto')?.id).toBe('paseto')
    expect(reg.get('basicAuth')?.id).toBe('basicAuth')
    expect(reg.get('awsSigv4')?.id).toBe('awsSigv4')
    expect(reg.get('secret')?.id).toBe('secret')
  })
})
