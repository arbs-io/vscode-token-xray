import { describe, expect, it } from 'vitest'
import { SshKeyAnalyzer } from './analyzer'

/* ------------------------------------------------------------------ *
 *  Helpers (mirrors the synthesis helpers in decoder.test.ts but kept
 *  local so each test file is self-contained).
 * ------------------------------------------------------------------ */

function uint32BE(n: number): Uint8Array {
  const out = new Uint8Array(4)
  out[0] = (n >>> 24) & 0xff
  out[1] = (n >>> 16) & 0xff
  out[2] = (n >>> 8) & 0xff
  out[3] = n & 0xff
  return out
}

function lenPrefixed(bytes: Uint8Array): Uint8Array {
  const len = uint32BE(bytes.length)
  const out = new Uint8Array(4 + bytes.length)
  out.set(len, 0)
  out.set(bytes, 4)
  return out
}

function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.codePointAt(i) ?? 0
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCodePoint(b)
  return btoa(s)
}

function rsaModulus(bits: number): Uint8Array {
  const totalBits = Math.ceil(bits / 8) * 8
  const byteLen = totalBits / 8
  const out = new Uint8Array(byteLen + 1)
  out[0] = 0x00
  const firstByteIndex = 1 + (byteLen - Math.ceil(bits / 8))
  const leadingBitInByte = ((bits - 1) % 8) + 1
  out[firstByteIndex] = 1 << (leadingBitInByte - 1)
  for (let i = firstByteIndex + 1; i < out.length; i++) out[i] = 0xaa
  return out
}

function rsaKeyLine(bits: number, comment?: string): string {
  const body = concat(
    lenPrefixed(ascii('ssh-rsa')),
    lenPrefixed(new Uint8Array([0x01, 0x00, 0x01])),
    lenPrefixed(rsaModulus(bits))
  )
  return comment ? `ssh-rsa ${bytesToBase64(body)} ${comment}` : `ssh-rsa ${bytesToBase64(body)}`
}

function ed25519Line(comment?: string): string {
  const pub = new Uint8Array(32)
  for (let i = 0; i < pub.length; i++) pub[i] = i
  const body = concat(lenPrefixed(ascii('ssh-ed25519')), lenPrefixed(pub))
  return comment ? `ssh-ed25519 ${bytesToBase64(body)} ${comment}` : `ssh-ed25519 ${bytesToBase64(body)}`
}

const ECDSA_POINT_LEN: Record<'nistp256' | 'nistp384' | 'nistp521', number> = {
  nistp256: 65,
  nistp384: 97,
  nistp521: 133,
}

function ecdsaLine(curve: 'nistp256' | 'nistp384' | 'nistp521'): string {
  const pointLen = ECDSA_POINT_LEN[curve]
  const point = new Uint8Array(pointLen)
  point[0] = 0x04
  for (let i = 1; i < pointLen; i++) point[i] = (i * 7) & 0xff
  const body = concat(
    lenPrefixed(ascii(`ecdsa-sha2-${curve}`)),
    lenPrefixed(ascii(curve)),
    lenPrefixed(point)
  )
  return `ecdsa-sha2-${curve} ${bytesToBase64(body)} ec@host`
}

function dssLine(): string {
  const big = new Uint8Array(64)
  for (let i = 0; i < big.length; i++) big[i] = (i + 1) & 0xff
  const body = concat(
    lenPrefixed(ascii('ssh-dss')),
    lenPrefixed(big),
    lenPrefixed(big.slice(0, 20)),
    lenPrefixed(big),
    lenPrefixed(big)
  )
  return `ssh-dss ${bytesToBase64(body)} legacy@host`
}

/* ------------------------------------------------------------------ *
 *  Tests
 * ------------------------------------------------------------------ */

describe('SshKeyAnalyzer', () => {
  const analyzer = new SshKeyAnalyzer()

  it('exposes id "sshKey" and a human name', () => {
    expect(analyzer.id).toBe('sshKey')
    expect(analyzer.name).toBe('OpenSSH public key')
  })

  it('detects an ssh-rsa line with byte range', () => {
    const text = rsaKeyLine(2048, 'user@host')
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBe(0)
    expect(matches[0].range?.end).toBe(text.length)
  })

  it('detects ssh-ed25519, ecdsa-sha2-nistpXXX, and ssh-dss', () => {
    expect(analyzer.detect(ed25519Line('a'))).toHaveLength(1)
    expect(analyzer.detect(ecdsaLine('nistp256'))).toHaveLength(1)
    expect(analyzer.detect(ecdsaLine('nistp384'))).toHaveLength(1)
    expect(analyzer.detect(ecdsaLine('nistp521'))).toHaveLength(1)
    expect(analyzer.detect(dssLine())).toHaveLength(1)
  })

  it('returns empty for unrelated text', () => {
    expect(analyzer.detect('')).toEqual([])
    expect(analyzer.detect('plain text without any key')).toEqual([])
  })

  it('skips lines whose embedded type disagrees with the prefix (no false positives)', () => {
    // Build a real ssh-rsa body but advertise the line as ssh-dss.
    const body = concat(
      lenPrefixed(ascii('ssh-rsa')),
      lenPrefixed(new Uint8Array([0x01, 0x00, 0x01])),
      lenPrefixed(rsaModulus(2048))
    )
    const line = `ssh-dss ${bytesToBase64(body)} mismatch`
    expect(analyzer.detect(line)).toEqual([])
  })

  it('skips garbage that merely starts with a supported prefix', () => {
    // "ssh-rsa AAAA..." but no valid wire encoding.
    expect(analyzer.detect('ssh-rsa AAAA')).toEqual([])
  })

  it('does not greedily match across two stacked key lines', () => {
    const text = `${rsaKeyLine(2048, 'a')}\n${ed25519Line('b')}`
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(2)
  })

  it('analyse exposes type, comment, and modulusBits for ssh-rsa', () => {
    const [m] = analyzer.detect(rsaKeyLine(2048, 'user@host'))
    const result = analyzer.analyze(m)
    expect(result.analyzerId).toBe('sshKey')
    expect(result.kind).toBe('OpenSSH public key')
    expect(result.sections).toHaveLength(1)
    expect(result.sections[0].id).toBe('key')
    const rows = result.sections[0].rows
    expect(rows.find((r) => r.key === 'type')?.value).toBe('ssh-rsa')
    expect(rows.find((r) => r.key === 'comment')?.value).toBe('user@host')
    expect(rows.find((r) => r.key === 'modulusBits')?.value).toBe(2048)
  })

  it('analyse omits the comment row when no comment is present', () => {
    const [m] = analyzer.detect(rsaKeyLine(2048))
    const result = analyzer.analyze(m)
    expect(result.sections[0].rows.find((r) => r.key === 'comment')).toBeUndefined()
  })

  it('analyse exposes the curve for ECDSA keys instead of modulusBits', () => {
    const [m] = analyzer.detect(ecdsaLine('nistp256'))
    const result = analyzer.analyze(m)
    const rows = result.sections[0].rows
    expect(rows.find((r) => r.key === 'curve')?.value).toBe('nistp256')
    expect(rows.find((r) => r.key === 'modulusBits')).toBeUndefined()
  })

  it('analyse emits sshKey.weakRsa for a 1024-bit RSA key', () => {
    const [m] = analyzer.detect(rsaKeyLine(1024, 'weak@host'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'sshKey.weakRsa')?.severity).toBe('error')
  })

  it('analyse emits sshKey.weakDsa (error) for ssh-dss', () => {
    const [m] = analyzer.detect(dssLine())
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'sshKey.weakDsa')?.severity).toBe('error')
  })

  it('analyse emits sshKey.ecdsa.curve (info) for ECDSA keys', () => {
    const [m] = analyzer.detect(ecdsaLine('nistp256'))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'sshKey.ecdsa.curve')?.severity).toBe('info')
  })

  it('analyse emits no findings for a healthy ed25519 key', () => {
    const [m] = analyzer.detect(ed25519Line('ok'))
    const result = analyzer.analyze(m)
    expect(result.findings).toEqual([])
  })

  it('analyse throws when handed text that cannot be decoded as an SSH key', () => {
    expect(() => analyzer.analyze({ text: 'ssh-rsa AAAA' })).toThrow(/does not look like/)
  })
})
