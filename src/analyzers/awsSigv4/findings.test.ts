import { describe, expect, it } from 'vitest'
import { findingsForSigv4 } from './findings'
import { Sigv4Components } from './parser'

function base(): Sigv4Components {
  return {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    date: '20130524',
    region: 'us-east-1',
    service: 's3',
    signedHeaders: ['host', 'x-amz-date'],
    signature: 'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024',
  }
}

describe('findingsForSigv4', () => {
  it('always emits awsSigv4.accessKeyExposed (warning) naming key id, region and service', () => {
    const findings = findingsForSigv4(base())
    const exposed = findings.find((f) => f.id === 'awsSigv4.accessKeyExposed')
    expect(exposed?.severity).toBe('warning')
    expect(exposed?.message).toContain('AKIAIOSFODNN7EXAMPLE')
    expect(exposed?.message).toContain('us-east-1')
    expect(exposed?.message).toContain('s3')
    expect(exposed?.docUrl).toMatch(/aws-signing/)
  })

  it('emits awsSigv4.session.token (info) when access key starts with ASIA', () => {
    const findings = findingsForSigv4({ ...base(), accessKeyId: 'ASIAIOSFODNN7EXAMPLE' })
    const session = findings.find((f) => f.id === 'awsSigv4.session.token')
    expect(session?.severity).toBe('info')
    expect(session?.message).toContain('ASIA')
  })

  it('does NOT emit awsSigv4.session.token for AKIA keys', () => {
    const findings = findingsForSigv4(base())
    expect(findings.find((f) => f.id === 'awsSigv4.session.token')).toBeUndefined()
  })

  it('emits awsSigv4.signedHeaders.missingHost (warning) when host is not signed', () => {
    const findings = findingsForSigv4({ ...base(), signedHeaders: ['x-amz-date', 'x-amz-content-sha256'] })
    const missing = findings.find((f) => f.id === 'awsSigv4.signedHeaders.missingHost')
    expect(missing?.severity).toBe('warning')
    expect(missing?.message).toMatch(/host/i)
  })

  it('does NOT emit awsSigv4.signedHeaders.missingHost when host is in the list', () => {
    const findings = findingsForSigv4(base())
    expect(findings.find((f) => f.id === 'awsSigv4.signedHeaders.missingHost')).toBeUndefined()
  })

  it('combines all findings for an ASIA key with missing host', () => {
    const findings = findingsForSigv4({
      ...base(),
      accessKeyId: 'ASIAIOSFODNN7EXAMPLE',
      signedHeaders: ['x-amz-date'],
    })
    const ids = findings.map((f) => f.id).sort()
    expect(ids).toEqual([
      'awsSigv4.accessKeyExposed',
      'awsSigv4.session.token',
      'awsSigv4.signedHeaders.missingHost',
    ])
  })
})
