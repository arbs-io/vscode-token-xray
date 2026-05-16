import { describe, expect, it } from 'vitest'
import { findingsForCavage, findingsForRfc9421 } from './findings'
import { CavageSig, Rfc9421Sig } from './parser'

const BASE_CAVAGE: CavageSig = {
  keyId: 'alice',
  algorithm: 'rsa-sha256',
  headers: ['(request-target)', 'host', 'date'],
  signature: 'base64==',
}

const BASE_RFC9421: Rfc9421Sig = {
  label: 'sig1',
  components: ['@method', '@path'],
  keyId: 'alice',
}

describe('findingsForCavage', () => {
  it('produces no findings for a healthy signature', () => {
    expect(findingsForCavage(BASE_CAVAGE)).toEqual([])
  })

  it('emits httpSignature.algorithm.weak for hmac-sha1', () => {
    const sig = { ...BASE_CAVAGE, algorithm: 'hmac-sha1' }
    const findings = findingsForCavage(sig)
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('httpSignature.algorithm.weak')
    expect(findings[0].severity).toBe('warning')
  })

  it('emits httpSignature.algorithm.weak for rsa-sha1', () => {
    const sig = { ...BASE_CAVAGE, algorithm: 'rsa-sha1' }
    const findings = findingsForCavage(sig)
    expect(findings.some((f) => f.id === 'httpSignature.algorithm.weak')).toBe(true)
  })

  it('matches the weak-algorithm check case-insensitively', () => {
    const sig = { ...BASE_CAVAGE, algorithm: 'HMAC-SHA1' }
    expect(findingsForCavage(sig).some((f) => f.id === 'httpSignature.algorithm.weak')).toBe(true)
  })

  it('emits httpSignature.algorithm.missing when algorithm is absent', () => {
    const sig: CavageSig = {
      keyId: 'alice',
      headers: ['(request-target)'],
      signature: 'b64==',
    }
    const findings = findingsForCavage(sig)
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('httpSignature.algorithm.missing')
    expect(findings[0].severity).toBe('info')
  })

  it('does not emit `algorithm.missing` when algorithm is present (even if weak)', () => {
    const sig = { ...BASE_CAVAGE, algorithm: 'rsa-sha1' }
    const findings = findingsForCavage(sig)
    expect(findings.some((f) => f.id === 'httpSignature.algorithm.missing')).toBe(false)
  })

  it('emits httpSignature.created.future when created is > 5 minutes ahead of now', () => {
    const now = 1_700_000_000_000
    const sig = { ...BASE_CAVAGE, created: Math.floor(now / 1000) + 3600 }
    const findings = findingsForCavage(sig, now)
    expect(findings.some((f) => f.id === 'httpSignature.created.future')).toBe(true)
  })

  it('does not emit `created.future` when created is within the 5-minute skew', () => {
    const now = 1_700_000_000_000
    const sig = { ...BASE_CAVAGE, created: Math.floor(now / 1000) + 60 }
    const findings = findingsForCavage(sig, now)
    expect(findings.some((f) => f.id === 'httpSignature.created.future')).toBe(false)
  })

  it('does not emit `created.future` when created is in the past', () => {
    const now = 1_700_000_000_000
    const sig = { ...BASE_CAVAGE, created: Math.floor(now / 1000) - 3600 }
    const findings = findingsForCavage(sig, now)
    expect(findings.some((f) => f.id === 'httpSignature.created.future')).toBe(false)
  })

  it('uses Date.now by default for the future check', () => {
    // No explicit `now` arg — pick a created value definitely far in
    // the past so the function takes the no-finding branch.
    const sig = { ...BASE_CAVAGE, created: 0 }
    expect(findingsForCavage(sig).some((f) => f.id === 'httpSignature.created.future')).toBe(false)
  })

  it('emits both `algorithm.weak` and `created.future` together when applicable', () => {
    const now = 1_700_000_000_000
    const sig: CavageSig = {
      ...BASE_CAVAGE,
      algorithm: 'hmac-sha1',
      created: Math.floor(now / 1000) + 3600,
    }
    const ids = findingsForCavage(sig, now).map((f) => f.id)
    expect(ids).toContain('httpSignature.algorithm.weak')
    expect(ids).toContain('httpSignature.created.future')
  })
})

describe('findingsForRfc9421', () => {
  it('produces no findings for a healthy signature', () => {
    expect(findingsForRfc9421(BASE_RFC9421)).toEqual([])
  })

  it('does NOT emit `algorithm.missing` for RFC 9421 even without an algorithm parameter', () => {
    const findings = findingsForRfc9421(BASE_RFC9421)
    expect(findings.some((f) => f.id === 'httpSignature.algorithm.missing')).toBe(false)
  })

  it('emits httpSignature.algorithm.weak when alg=rsa-sha1', () => {
    const sig: Rfc9421Sig = { ...BASE_RFC9421, algorithm: 'rsa-sha1' }
    const findings = findingsForRfc9421(sig)
    expect(findings.some((f) => f.id === 'httpSignature.algorithm.weak')).toBe(true)
  })

  it('emits httpSignature.created.future when created is far in the future', () => {
    const now = 1_700_000_000_000
    const sig: Rfc9421Sig = { ...BASE_RFC9421, created: Math.floor(now / 1000) + 7200 }
    const findings = findingsForRfc9421(sig, now)
    expect(findings.some((f) => f.id === 'httpSignature.created.future')).toBe(true)
  })

  it('does not emit `created.future` when created is recent', () => {
    const now = 1_700_000_000_000
    const sig: Rfc9421Sig = { ...BASE_RFC9421, created: Math.floor(now / 1000) }
    expect(findingsForRfc9421(sig, now).some((f) => f.id === 'httpSignature.created.future')).toBe(false)
  })

  it('uses Date.now by default for the future check', () => {
    expect(findingsForRfc9421(BASE_RFC9421).some((f) => f.id === 'httpSignature.created.future')).toBe(false)
  })
})
