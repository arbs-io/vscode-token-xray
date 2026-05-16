import { describe, expect, it } from 'vitest'
import { decodeSshKey } from './decoder'

/* ------------------------------------------------------------------ *
 *  Test helpers — build OpenSSH wire-format keys from scratch so we
 *  can exercise both well-formed and deliberately mangled inputs
 *  without having to ship binary fixtures.
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
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
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
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

/** Build an RSA modulus with `bits` significant bits, zero-padded. */
function rsaModulus(bits: number): Uint8Array {
  const totalBits = Math.ceil(bits / 8) * 8
  const byteLen = totalBits / 8
  const out = new Uint8Array(byteLen + 1) // +1 for ssh-mpint sign-padding byte
  // Index 0 is the padding 0x00 byte that keeps the value non-negative.
  out[0] = 0x00
  // Place the leading set bit at the right position so significantBitLength
  // returns exactly `bits`.
  const firstByteIndex = 1 + (byteLen - Math.ceil(bits / 8))
  const leadingBitInByte = ((bits - 1) % 8) + 1 // 1..8
  out[firstByteIndex] = 1 << (leadingBitInByte - 1)
  // Fill the rest with arbitrary non-zero bytes so the bit count below the
  // MSB doesn't accidentally trim.
  for (let i = firstByteIndex + 1; i < out.length; i++) out[i] = 0xaa
  return out
}

function rsaKey(bits: number): Uint8Array {
  return concat(
    lenPrefixed(ascii('ssh-rsa')),
    lenPrefixed(new Uint8Array([0x01, 0x00, 0x01])), // exponent = 65537
    lenPrefixed(rsaModulus(bits))
  )
}

function ed25519Key(): Uint8Array {
  const pub = new Uint8Array(32)
  for (let i = 0; i < pub.length; i++) pub[i] = i
  return concat(lenPrefixed(ascii('ssh-ed25519')), lenPrefixed(pub))
}

function ecdsaKey(curve: 'nistp256' | 'nistp384' | 'nistp521'): Uint8Array {
  const pointLen = curve === 'nistp256' ? 65 : curve === 'nistp384' ? 97 : 133
  const point = new Uint8Array(pointLen)
  point[0] = 0x04 // uncompressed-point marker
  for (let i = 1; i < pointLen; i++) point[i] = (i * 7) & 0xff
  return concat(
    lenPrefixed(ascii(`ecdsa-sha2-${curve}`)),
    lenPrefixed(ascii(curve)),
    lenPrefixed(point)
  )
}

function dssKey(): Uint8Array {
  const big = new Uint8Array(64)
  for (let i = 0; i < big.length; i++) big[i] = (i + 1) & 0xff
  return concat(
    lenPrefixed(ascii('ssh-dss')),
    lenPrefixed(big),
    lenPrefixed(big.slice(0, 20)),
    lenPrefixed(big),
    lenPrefixed(big)
  )
}

function line(type: string, body: Uint8Array, comment?: string): string {
  const b64 = bytesToBase64(body)
  return comment ? `${type} ${b64} ${comment}` : `${type} ${b64}`
}

/* ------------------------------------------------------------------ *
 *  Tests
 * ------------------------------------------------------------------ */

describe('decodeSshKey — positives per algorithm', () => {
  it('decodes ssh-rsa with the expected modulus bit length', () => {
    const decoded = decodeSshKey(line('ssh-rsa', rsaKey(2048), 'user@host'))
    expect(decoded?.type).toBe('ssh-rsa')
    expect(decoded?.modulusBits).toBe(2048)
    expect(decoded?.comment).toBe('user@host')
  })

  it('decodes ssh-rsa without a comment', () => {
    const decoded = decodeSshKey(line('ssh-rsa', rsaKey(3072)))
    expect(decoded?.modulusBits).toBe(3072)
    expect(decoded?.comment).toBeUndefined()
  })

  it('decodes a weak ssh-rsa key and exposes the smaller bit length', () => {
    const decoded = decodeSshKey(line('ssh-rsa', rsaKey(1024)))
    expect(decoded?.modulusBits).toBe(1024)
  })

  it('decodes ssh-ed25519 with a 32-byte public key', () => {
    const decoded = decodeSshKey(line('ssh-ed25519', ed25519Key(), 'box'))
    expect(decoded?.type).toBe('ssh-ed25519')
    expect(decoded?.comment).toBe('box')
    expect(decoded?.modulusBits).toBeUndefined()
    expect(decoded?.curve).toBeUndefined()
  })

  it('decodes ecdsa-sha2-nistp256 and surfaces its curve', () => {
    const decoded = decodeSshKey(line('ecdsa-sha2-nistp256', ecdsaKey('nistp256')))
    expect(decoded?.type).toBe('ecdsa-sha2-nistp256')
    expect(decoded?.curve).toBe('nistp256')
  })

  it('decodes ecdsa-sha2-nistp384', () => {
    const decoded = decodeSshKey(line('ecdsa-sha2-nistp384', ecdsaKey('nistp384')))
    expect(decoded?.curve).toBe('nistp384')
  })

  it('decodes ecdsa-sha2-nistp521', () => {
    const decoded = decodeSshKey(line('ecdsa-sha2-nistp521', ecdsaKey('nistp521')))
    expect(decoded?.curve).toBe('nistp521')
  })

  it('decodes ssh-dss without needing further parsing', () => {
    const decoded = decodeSshKey(line('ssh-dss', dssKey(), 'legacy@host'))
    expect(decoded?.type).toBe('ssh-dss')
    expect(decoded?.comment).toBe('legacy@host')
  })

  it('trims surrounding whitespace and tolerates leading spaces', () => {
    const decoded = decodeSshKey(`   ${line('ssh-ed25519', ed25519Key())}   `)
    expect(decoded?.type).toBe('ssh-ed25519')
  })
})

describe('decodeSshKey — negatives', () => {
  it('returns undefined for non-string input', () => {
    expect(decodeSshKey(undefined as unknown as string)).toBeUndefined()
    expect(decodeSshKey(42 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for empty / whitespace-only input', () => {
    expect(decodeSshKey('')).toBeUndefined()
    expect(decodeSshKey('   ')).toBeUndefined()
  })

  it('returns undefined for unrecognised algorithm prefix', () => {
    expect(decodeSshKey('rsa-sha2-512 AAAAB3NzaC1yc2EAAAA')).toBeUndefined()
  })

  it('returns undefined when only the type token is present', () => {
    expect(decodeSshKey('ssh-rsa')).toBeUndefined()
  })

  it('returns undefined when the base64 body is empty', () => {
    expect(decodeSshKey('ssh-rsa  comment')).toBeUndefined()
  })

  it('returns undefined for non-base64 characters in the body', () => {
    expect(decodeSshKey('ssh-rsa @@@!!!')).toBeUndefined()
  })

  it('returns undefined when the embedded type disagrees with the prefix', () => {
    // Encode a perfectly valid ssh-rsa body but advertise it as ssh-dss.
    const body = bytesToBase64(rsaKey(2048))
    expect(decodeSshKey(`ssh-dss ${body}`)).toBeUndefined()
  })

  it('returns undefined for a truncated body (missing modulus field)', () => {
    // Just the type field, no e/n.
    const truncated = bytesToBase64(lenPrefixed(ascii('ssh-rsa')))
    expect(decodeSshKey(`ssh-rsa ${truncated}`)).toBeUndefined()
  })

  it('returns undefined when an ssh-rsa body claims an oversized field length', () => {
    const evil = bytesToBase64(
      concat(
        lenPrefixed(ascii('ssh-rsa')),
        uint32BE(0x7fffffff) // claimed length larger than the buffer
      )
    )
    expect(decodeSshKey(`ssh-rsa ${evil}`)).toBeUndefined()
  })

  it('returns undefined when an ssh-rsa body claims a negative field length (high bit set)', () => {
    const evil = bytesToBase64(
      concat(
        lenPrefixed(ascii('ssh-rsa')),
        // 0xffffffff — interpreted as a signed int this becomes -1.
        new Uint8Array([0xff, 0xff, 0xff, 0xff])
      )
    )
    expect(decodeSshKey(`ssh-rsa ${evil}`)).toBeUndefined()
  })

  it('returns undefined for an ed25519 body whose pubkey is not 32 bytes', () => {
    const bad = bytesToBase64(
      concat(lenPrefixed(ascii('ssh-ed25519')), lenPrefixed(new Uint8Array(16)))
    )
    expect(decodeSshKey(`ssh-ed25519 ${bad}`)).toBeUndefined()
  })

  it('returns undefined for an ecdsa body whose curve identifier disagrees with the type', () => {
    const bad = bytesToBase64(
      concat(
        lenPrefixed(ascii('ecdsa-sha2-nistp256')),
        lenPrefixed(ascii('nistp384')), // wrong curve
        lenPrefixed(new Uint8Array(65))
      )
    )
    expect(decodeSshKey(`ecdsa-sha2-nistp256 ${bad}`)).toBeUndefined()
  })

  it('returns undefined for an ecdsa body whose point is empty', () => {
    const bad = bytesToBase64(
      concat(
        lenPrefixed(ascii('ecdsa-sha2-nistp256')),
        lenPrefixed(ascii('nistp256')),
        lenPrefixed(new Uint8Array(0))
      )
    )
    expect(decodeSshKey(`ecdsa-sha2-nistp256 ${bad}`)).toBeUndefined()
  })

  it('returns undefined for a truncated ssh-dss body', () => {
    const bad = bytesToBase64(concat(lenPrefixed(ascii('ssh-dss')), lenPrefixed(new Uint8Array(8))))
    expect(decodeSshKey(`ssh-dss ${bad}`)).toBeUndefined()
  })
})
