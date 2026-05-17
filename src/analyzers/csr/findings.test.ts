import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeCsr } from './decoder'
import { evaluateCsr, findingsForParseFailure } from './findings'

const FIX_DIR = join(__dirname, 'fixtures')
const pem = (name: string): string => readFileSync(join(FIX_DIR, name), 'utf8')

describe('evaluateCsr', () => {
  it('emits no errors for a healthy RSA-2048 CSR with SAN', () => {
    const decoded = decodeCsr(pem('good.pem'))!
    const findings = evaluateCsr(decoded)
    expect(findings.find((f) => f.severity === 'error')).toBeUndefined()
  })

  it('flags csr.key.weakRsa (error) when RSA bits < 2048', () => {
    const decoded = decodeCsr(pem('weak-key.pem'))!
    const finding = evaluateCsr(decoded).find((f) => f.id === 'csr.key.weakRsa')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('error')
    expect(finding?.message).toContain('RSA-1024')
  })

  it('flags csr.san.missing (warning) when no SAN extension was requested', () => {
    const decoded = decodeCsr(pem('no-san.pem'))!
    const finding = evaluateCsr(decoded).find((f) => f.id === 'csr.san.missing')
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('warning')
  })

  it('does not flag csr.san.missing when SANs are present', () => {
    const decoded = decodeCsr(pem('good.pem'))!
    expect(evaluateCsr(decoded).find((f) => f.id === 'csr.san.missing')).toBeUndefined()
  })

  it('does not flag csr.key.weakRsa for a 2048-bit key', () => {
    const decoded = decodeCsr(pem('good.pem'))!
    expect(evaluateCsr(decoded).find((f) => f.id === 'csr.key.weakRsa')).toBeUndefined()
  })

  it('does not flag csr.key.weakRsa for a non-RSA algorithm', () => {
    const findings = evaluateCsr({
      subject: 'CN=ec.example.test',
      keyAlgorithm: 'ec',
      curve: 'P-256',
      subjectAltNames: ['DNS:ec.example.test'],
    })
    expect(findings.find((f) => f.id === 'csr.key.weakRsa')).toBeUndefined()
  })
})

describe('findingsForParseFailure', () => {
  it('emits csr.parse.failed as a warning', () => {
    const [finding] = findingsForParseFailure()
    expect(finding.id).toBe('csr.parse.failed')
    expect(finding.severity).toBe('warning')
    expect(finding.docUrl).toContain('rfc2986')
  })
})
