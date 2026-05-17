import { describe, expect, it } from 'vitest'
import { DecodedPaseto } from './decoder'
import { evaluatePaseto } from './findings'

function decoded(overrides: Partial<DecodedPaseto>): DecodedPaseto {
  return {
    version: 'v4',
    purpose: 'public',
    payload: 'placeholder',
    payloadInvalid: false,
    raw: 'v4.public.placeholder',
    ...overrides,
  }
}

describe('evaluatePaseto', () => {
  it('emits no findings for a healthy v3.public token', () => {
    const findings = evaluatePaseto(decoded({ version: 'v3', purpose: 'public', claims: { sub: 'a' } }))
    expect(findings).toEqual([])
  })

  it('emits no findings for a healthy v4.public token', () => {
    const findings = evaluatePaseto(decoded({ version: 'v4', purpose: 'public', claims: { sub: 'a' } }))
    expect(findings).toEqual([])
  })

  it('flags v1 as deprecated (info)', () => {
    const findings = evaluatePaseto(decoded({ version: 'v1', purpose: 'public', claims: { sub: 'a' } }))
    const hit = findings.find((f) => f.id === 'paseto.version.deprecated')
    expect(hit?.severity).toBe('info')
  })

  it('flags v2 as deprecated (info)', () => {
    const findings = evaluatePaseto(decoded({ version: 'v2', purpose: 'public', claims: { sub: 'a' } }))
    const hit = findings.find((f) => f.id === 'paseto.version.deprecated')
    expect(hit?.severity).toBe('info')
  })

  it('does NOT flag v3 / v4 as deprecated', () => {
    expect(evaluatePaseto(decoded({ version: 'v3' })).some((f) => f.id === 'paseto.version.deprecated')).toBe(false)
    expect(evaluatePaseto(decoded({ version: 'v4' })).some((f) => f.id === 'paseto.version.deprecated')).toBe(false)
  })

  it('emits paseto.purpose.local (info) for local tokens', () => {
    const findings = evaluatePaseto(decoded({ version: 'v4', purpose: 'local' }))
    const hit = findings.find((f) => f.id === 'paseto.purpose.local')
    expect(hit?.severity).toBe('info')
    expect(hit?.message).toMatch(/encrypted/i)
  })

  it('does NOT emit paseto.purpose.local for public tokens', () => {
    const findings = evaluatePaseto(decoded({ purpose: 'public' }))
    expect(findings.some((f) => f.id === 'paseto.purpose.local')).toBe(false)
  })

  it('emits paseto.payload.invalid (warning) when payloadInvalid is set', () => {
    const findings = evaluatePaseto(decoded({ purpose: 'public', payloadInvalid: true }))
    const hit = findings.find((f) => f.id === 'paseto.payload.invalid')
    expect(hit?.severity).toBe('warning')
  })

  it('stacks deprecated + local findings on a v2.local token', () => {
    const findings = evaluatePaseto(decoded({ version: 'v2', purpose: 'local' }))
    const ids = findings.map((f) => f.id).sort()
    expect(ids).toEqual(['paseto.purpose.local', 'paseto.version.deprecated'])
  })

  it('attaches a docUrl on the version-deprecated finding', () => {
    const findings = evaluatePaseto(decoded({ version: 'v1', purpose: 'public', claims: { sub: 'a' } }))
    const hit = findings.find((f) => f.id === 'paseto.version.deprecated')
    expect(hit?.docUrl).toMatch(/paseto/i)
  })
})
