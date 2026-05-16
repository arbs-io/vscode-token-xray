import { describe, expect, it } from 'vitest'
import { findingsForDecodedBasic, findingsForMalformedBasic, maskPassword } from './findings'

describe('maskPassword', () => {
  it('keeps the last 2 characters by default and prefixes 8 stars', () => {
    expect(maskPassword('hunter2')).toBe('********r2')
    expect(maskPassword('s3cretpass')).toBe('********ss')
  })

  it('handles short passwords gracefully (cannot reveal more than the length)', () => {
    expect(maskPassword('ab')).toBe('********ab')
    expect(maskPassword('a')).toBe('********a')
  })

  it('handles an empty password (8 stars + nothing to reveal)', () => {
    expect(maskPassword('')).toBe('********')
  })

  it('respects the keep parameter when provided', () => {
    expect(maskPassword('abcdef', 4)).toBe('********cdef')
    expect(maskPassword('abcdef', 0)).toBe('********')
  })
})

describe('findingsForDecodedBasic', () => {
  it('emits exactly one basic.cred.plaintext finding with error severity', () => {
    const findings = findingsForDecodedBasic({ user: 'alice', password: 'wonderland' })
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('basic.cred.plaintext')
    expect(findings[0].severity).toBe('error')
  })

  it('embeds the decoded username in the message verbatim', () => {
    const findings = findingsForDecodedBasic({ user: 'admin', password: 'pw' })
    expect(findings[0].message).toContain('"admin"')
  })

  it('masks the password to the last 2 chars in the message', () => {
    const findings = findingsForDecodedBasic({ user: 'admin', password: 'supersecret' })
    expect(findings[0].message).toContain('********et')
    expect(findings[0].message).not.toContain('supersecret')
  })

  it('attaches an RFC 7617 docUrl', () => {
    const findings = findingsForDecodedBasic({ user: 'a', password: 'b' })
    expect(findings[0].docUrl).toMatch(/rfc7617/)
  })
})

describe('findingsForMalformedBasic', () => {
  it('emits a single basic.cred.malformed finding with warning severity', () => {
    const findings = findingsForMalformedBasic()
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('basic.cred.malformed')
    expect(findings[0].severity).toBe('warning')
  })

  it('explains why the credential could not be decoded', () => {
    const findings = findingsForMalformedBasic()
    expect(findings[0].message).toMatch(/decode|user:password/i)
  })
})
