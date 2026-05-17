import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeJwkInput } from './decoder'
import { evaluateJwk } from './findings'

const FIX_DIR = join(__dirname, 'fixtures')
const read = (n: string) => readFileSync(join(FIX_DIR, n), 'utf8')

describe('evaluateJwk', () => {
  it('no errors for a healthy RSA-2048 public JWK', () => {
    const findings = evaluateJwk(decodeJwkInput(read('rsa-public.json')))
    expect(findings.find((f) => f.severity === 'error')).toBeUndefined()
  })

  it('flags weak RSA key', () => {
    const findings = evaluateJwk(decodeJwkInput(read('rsa-weak.json')))
    expect(findings.find((f) => f.id.endsWith('rsa.key.weak'))?.severity).toBe('error')
  })

  it('flags private material as error', () => {
    const findings = evaluateJwk(decodeJwkInput(read('ec-private.json')))
    expect(findings.find((f) => f.id.endsWith('private.present'))?.severity).toBe('error')
  })

  it('flags missing kid as info', () => {
    const findings = evaluateJwk(decodeJwkInput('{"kty":"RSA","n":"AQAB","e":"AQAB"}'))
    expect(findings.find((f) => f.id.endsWith('kid.missing'))?.severity).toBe('info')
  })

  it('flags weak curves', () => {
    const findings = evaluateJwk(decodeJwkInput('{"kty":"EC","crv":"P-192","kid":"k"}'))
    expect(findings.some((f) => f.id.endsWith('curve.weak'))).toBe(true)
  })

  it('flags unknown curves', () => {
    const findings = evaluateJwk(decodeJwkInput('{"kty":"EC","crv":"P-1","kid":"k"}'))
    expect(findings.some((f) => f.id.endsWith('curve.unknown'))).toBe(true)
  })

  it('flags weak symmetric keys (oct < 128 bits)', () => {
    // 8-byte oct key
    const findings = evaluateJwk(decodeJwkInput('{"kty":"oct","k":"YWJjZGVmZw","kid":"k"}'))
    expect(findings.find((f) => f.id.endsWith('oct.key.weak'))?.severity).toBe('error')
  })

  it('flags invalid "use"', () => {
    const findings = evaluateJwk(decodeJwkInput('{"kty":"oct","k":"YWJjZGVmZ2hpamtsbW5vcA","kid":"k","use":"junk"}'))
    expect(findings.some((f) => f.id.endsWith('use.invalid'))).toBe(true)
  })

  it('flags unknown kty as warning', () => {
    const findings = evaluateJwk(decodeJwkInput('{"kty":"XYZ"}'))
    expect(findings.find((f) => f.id.endsWith('kty.unknown'))?.severity).toBe('warning')
  })

  it('flags empty JWKS', () => {
    const findings = evaluateJwk(decodeJwkInput('{"keys":[]}'))
    expect(findings.find((f) => f.id === 'jwks.empty')).toBeDefined()
  })

  it('prefixes findings per-key inside a JWKS', () => {
    const findings = evaluateJwk(decodeJwkInput(read('jwks.json')))
    // both keys have a kid (set in fixtures) so we expect no kid.missing
    expect(findings.every((f) => !f.id.endsWith('kid.missing'))).toBe(true)
  })

  it('flags missing modulus on RSA', () => {
    const findings = evaluateJwk(decodeJwkInput('{"kty":"RSA","kid":"k","e":"AQAB"}'))
    expect(findings.some((f) => f.id.endsWith('rsa.modulus.missing'))).toBe(true)
  })
})
