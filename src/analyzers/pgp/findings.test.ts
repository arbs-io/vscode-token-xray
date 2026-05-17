import { describe, expect, it } from 'vitest'
import { evaluatePgp } from './findings'

describe('evaluatePgp', () => {
  it('emits pgp.privateKey.present (error) for a PRIVATE KEY BLOCK', () => {
    const findings = evaluatePgp({
      blockType: 'PRIVATE KEY BLOCK',
      headers: {},
      firstPacketTag: 0xc5,
    })
    const f = findings.find((x) => x.id === 'pgp.privateKey.present')
    expect(f?.severity).toBe('error')
    expect(f?.docUrl).toContain('rfc9580')
  })

  it('emits pgp.message.encrypted (info) for a MESSAGE block', () => {
    const findings = evaluatePgp({
      blockType: 'MESSAGE',
      headers: {},
      firstPacketTag: 0xc1,
    })
    const f = findings.find((x) => x.id === 'pgp.message.encrypted')
    expect(f?.severity).toBe('info')
  })

  it('does not emit pgp.privateKey.present for a PUBLIC KEY BLOCK', () => {
    const findings = evaluatePgp({
      blockType: 'PUBLIC KEY BLOCK',
      headers: {},
      firstPacketTag: 0xc6,
    })
    expect(findings.find((x) => x.id === 'pgp.privateKey.present')).toBeUndefined()
  })

  it('does not emit pgp.message.encrypted for a SIGNATURE block', () => {
    const findings = evaluatePgp({
      blockType: 'SIGNATURE',
      headers: {},
      firstPacketTag: 0xc2,
    })
    expect(findings.find((x) => x.id === 'pgp.message.encrypted')).toBeUndefined()
  })

  it('emits pgp.armor.malformed (warning) when the body did not decode (no firstPacketTag)', () => {
    const findings = evaluatePgp({
      blockType: 'PUBLIC KEY BLOCK',
      headers: {},
    })
    const f = findings.find((x) => x.id === 'pgp.armor.malformed')
    expect(f?.severity).toBe('warning')
  })

  it('emits pgp.armor.malformed when the first packet tag bit 7 is 0', () => {
    // 0x40 has bit 6 set but bit 7 clear — invalid packet header.
    const findings = evaluatePgp({
      blockType: 'PUBLIC KEY BLOCK',
      headers: {},
      firstPacketTag: 0x40,
    })
    const f = findings.find((x) => x.id === 'pgp.armor.malformed')
    expect(f?.severity).toBe('warning')
  })

  it('does not emit pgp.armor.malformed when the first packet tag bit 7 is 1', () => {
    const findings = evaluatePgp({
      blockType: 'PUBLIC KEY BLOCK',
      headers: {},
      firstPacketTag: 0x80,
    })
    expect(findings.find((x) => x.id === 'pgp.armor.malformed')).toBeUndefined()
  })

  it('does not emit pgp.armor.malformed for a SIGNED MESSAGE without firstPacketTag', () => {
    // Cleartext-signed messages don't have a base64 body to decode —
    // missing firstPacketTag is the expected shape.
    const findings = evaluatePgp({
      blockType: 'SIGNED MESSAGE',
      headers: {},
    })
    expect(findings.find((x) => x.id === 'pgp.armor.malformed')).toBeUndefined()
  })

  it('a PRIVATE KEY BLOCK with a malformed body emits both findings', () => {
    const findings = evaluatePgp({
      blockType: 'PRIVATE KEY BLOCK',
      headers: {},
    })
    expect(findings.find((x) => x.id === 'pgp.privateKey.present')).toBeDefined()
    expect(findings.find((x) => x.id === 'pgp.armor.malformed')).toBeDefined()
  })
})
