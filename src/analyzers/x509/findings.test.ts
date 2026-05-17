import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { decodeX509 } from './decoder'
import { evaluateX509 } from './findings'

const FIX_DIR = join(__dirname, 'fixtures')
const pem = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')
const NOW = Date.UTC(2026, 0, 1)

describe('evaluateX509', () => {
  it('produces no errors for a healthy cert valid years out', () => {
    const findings = evaluateX509(decodeX509(pem('good.pem')), { now: NOW })
    expect(findings.find((f) => f.severity === 'error')).toBeUndefined()
  })

  it('flags weak RSA key as error', () => {
    const findings = evaluateX509(decodeX509(pem('weak-key.pem')), { now: NOW })
    expect(findings.find((f) => f.id === 'x509.key.weakRsa')?.severity).toBe('error')
  })

  it('flags SHA-1 signature as error', () => {
    const findings = evaluateX509(decodeX509(pem('sha1.pem')), { now: NOW })
    expect(findings.find((f) => f.id === 'x509.signature.weakAlgorithm')?.severity).toBe('error')
  })

  it('flags expired certificates as error', () => {
    const findings = evaluateX509(decodeX509(pem('expired.pem')), { now: NOW })
    expect(findings.find((f) => f.id === 'x509.validity.expired')?.severity).toBe('error')
  })

  it('flags self-signed certs as info', () => {
    const findings = evaluateX509(decodeX509(pem('good.pem')), { now: NOW })
    expect(findings.find((f) => f.id === 'x509.signature.selfSigned')?.severity).toBe('info')
  })

  it('flags missing SAN when cert has none', () => {
    const findings = evaluateX509(decodeX509(pem('weak-key.pem')), { now: NOW })
    expect(findings.find((f) => f.id === 'x509.san.missing')).toBeDefined()
  })

  it('flags expiringSoon when validTo is within 30 days', () => {
    // good.pem is valid for 10 years; simulate "now" 29 days before notAfter.
    const decoded = decodeX509(pem('good.pem'))
    const notAfterMs = Date.parse(decoded.validTo)
    const findings = evaluateX509(decoded, { now: notAfterMs - 24 * 60 * 60 * 1000 })
    expect(findings.find((f) => f.id === 'x509.validity.expiringSoon')?.severity).toBe('warning')
  })

  it('flags notYetValid when now < validFrom', () => {
    const decoded = decodeX509(pem('good.pem'))
    const before = Date.parse(decoded.validFrom) - 60_000
    const findings = evaluateX509(decoded, { now: before })
    expect(findings.find((f) => f.id === 'x509.validity.notYetValid')?.severity).toBe('warning')
  })
})
