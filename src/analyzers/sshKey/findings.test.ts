import { describe, expect, it } from 'vitest'
import { evaluateSshKey } from './findings'

describe('evaluateSshKey', () => {
  it('emits sshKey.weakDsa (error) for ssh-dss', () => {
    const findings = evaluateSshKey({ type: 'ssh-dss' })
    const f = findings.find((x) => x.id === 'sshKey.weakDsa')
    expect(f?.severity).toBe('error')
    expect(f?.docUrl).toContain('rfc4253')
  })

  it('emits sshKey.weakRsa (error) when RSA modulus is below 2048 bits', () => {
    const findings = evaluateSshKey({ type: 'ssh-rsa', modulusBits: 1024 })
    const f = findings.find((x) => x.id === 'sshKey.weakRsa')
    expect(f?.severity).toBe('error')
    expect(f?.message).toContain('1024')
  })

  it('does not emit sshKey.weakRsa for a 2048-bit RSA key', () => {
    const findings = evaluateSshKey({ type: 'ssh-rsa', modulusBits: 2048 })
    expect(findings.find((x) => x.id === 'sshKey.weakRsa')).toBeUndefined()
  })

  it('does not emit sshKey.weakRsa for a 4096-bit RSA key', () => {
    const findings = evaluateSshKey({ type: 'ssh-rsa', modulusBits: 4096 })
    expect(findings.find((x) => x.id === 'sshKey.weakRsa')).toBeUndefined()
  })

  it('does not emit sshKey.weakRsa when modulusBits is missing', () => {
    const findings = evaluateSshKey({ type: 'ssh-rsa' })
    expect(findings.find((x) => x.id === 'sshKey.weakRsa')).toBeUndefined()
  })

  it('emits sshKey.ecdsa.curve (info) for ECDSA keys', () => {
    const findings = evaluateSshKey({ type: 'ecdsa-sha2-nistp256', curve: 'nistp256' })
    const f = findings.find((x) => x.id === 'sshKey.ecdsa.curve')
    expect(f?.severity).toBe('info')
    expect(f?.message).toContain('nistp256')
  })

  it('emits sshKey.ecdsa.curve for P-384 and P-521', () => {
    expect(
      evaluateSshKey({ type: 'ecdsa-sha2-nistp384', curve: 'nistp384' }).find(
        (x) => x.id === 'sshKey.ecdsa.curve'
      )?.message
    ).toContain('nistp384')
    expect(
      evaluateSshKey({ type: 'ecdsa-sha2-nistp521', curve: 'nistp521' }).find(
        (x) => x.id === 'sshKey.ecdsa.curve'
      )?.message
    ).toContain('nistp521')
  })

  it('emits no findings for a healthy ed25519 key', () => {
    expect(evaluateSshKey({ type: 'ssh-ed25519' })).toEqual([])
  })

  it('emits no findings for a healthy 4096-bit RSA key', () => {
    expect(evaluateSshKey({ type: 'ssh-rsa', modulusBits: 4096 })).toEqual([])
  })
})
