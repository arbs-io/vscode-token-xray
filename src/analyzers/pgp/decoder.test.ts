import { describe, expect, it } from 'vitest'
import { decodePgp } from './decoder'

/* ------------------------------------------------------------------ *
 *  Test helpers — synthesise small armored blocks without depending on
 *  a real GnuPG fixture. Each helper takes a packet-tag byte so we can
 *  exercise the malformed-armor path too.
 * ------------------------------------------------------------------ */

function bytesToBase64(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

function armor(blockType: string, body: string, headers?: Record<string, string>): string {
  const headerLines = headers
    ? Object.entries(headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n') + '\n'
    : ''
  const bodySection = headers ? `\n${body}` : body
  return (
    `-----BEGIN PGP ${blockType}-----\n` +
    headerLines +
    `\n` +
    bodySection +
    `\n=AAAA\n` +
    `-----END PGP ${blockType}-----`
  )
}

function armorWithTag(blockType: string, tag: number, headers?: Record<string, string>): string {
  const body = bytesToBase64(new Uint8Array([tag, 0x00, 0x00]))
  return armor(blockType, body, headers)
}

/* ------------------------------------------------------------------ *
 *  Positive cases — one per supported block type
 * ------------------------------------------------------------------ */

describe('decodePgp — positive per block type', () => {
  it('decodes a PUBLIC KEY BLOCK', () => {
    const blob = armorWithTag('PUBLIC KEY BLOCK', 0xc6)
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('PUBLIC KEY BLOCK')
    expect(decoded?.firstPacketTag).toBe(0xc6)
  })

  it('decodes a PRIVATE KEY BLOCK', () => {
    const blob = armorWithTag('PRIVATE KEY BLOCK', 0xc5)
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('PRIVATE KEY BLOCK')
    expect(decoded?.firstPacketTag).toBe(0xc5)
  })

  it('decodes a SIGNATURE block', () => {
    const blob = armorWithTag('SIGNATURE', 0xc2)
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('SIGNATURE')
    expect(decoded?.firstPacketTag).toBe(0xc2)
  })

  it('decodes a MESSAGE block', () => {
    const blob = armorWithTag('MESSAGE', 0xc1)
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('MESSAGE')
    expect(decoded?.firstPacketTag).toBe(0xc1)
  })

  it('decodes a SIGNED MESSAGE (cleartext) without a first packet tag', () => {
    // Cleartext-signed messages have a body that isn't base64 — they
    // contain the cleartext + an inner SIGNATURE block. Just check that
    // the BEGIN/END markers parse and that we don't attempt a body
    // decode.
    const blob =
      `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello world.\n-----END PGP SIGNED MESSAGE-----`
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('SIGNED MESSAGE')
    expect(decoded?.firstPacketTag).toBeUndefined()
    expect(decoded?.headers['Hash']).toBe('SHA256')
  })
})

/* ------------------------------------------------------------------ *
 *  Header parsing
 * ------------------------------------------------------------------ */

describe('decodePgp — header parsing', () => {
  it('captures Version and Comment headers', () => {
    const blob = armorWithTag('PUBLIC KEY BLOCK', 0xc6, {
      Version: 'GnuPG v2.4.0',
      Comment: 'example@host',
    })
    const decoded = decodePgp(blob)
    expect(decoded?.headers['Version']).toBe('GnuPG v2.4.0')
    expect(decoded?.headers['Comment']).toBe('example@host')
  })

  it('returns an empty headers map when no headers are present', () => {
    const body = bytesToBase64(new Uint8Array([0xc6]))
    const blob = `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${body}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----`
    const decoded = decodePgp(blob)
    expect(decoded?.headers).toEqual({})
    expect(decoded?.firstPacketTag).toBe(0xc6)
  })

  it('treats a line that is not "Key: Value" as the start of the body', () => {
    // No blank line between BEGIN and body — first content line must be
    // treated as body, not header.
    const body = bytesToBase64(new Uint8Array([0xc6]))
    const blob = `-----BEGIN PGP PUBLIC KEY BLOCK-----\n${body}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----`
    const decoded = decodePgp(blob)
    expect(decoded?.headers).toEqual({})
    expect(decoded?.firstPacketTag).toBe(0xc6)
  })

  it('strips the optional =CRC24 line when computing the body', () => {
    const body = bytesToBase64(new Uint8Array([0xc6, 0x01, 0x02]))
    const blob =
      `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${body}\n=ABCD\n-----END PGP PUBLIC KEY BLOCK-----`
    const decoded = decodePgp(blob)
    expect(decoded?.firstPacketTag).toBe(0xc6)
  })
})

/* ------------------------------------------------------------------ *
 *  Negative cases
 * ------------------------------------------------------------------ */

describe('decodePgp — negatives', () => {
  it('returns undefined for non-string input', () => {
    expect(decodePgp(undefined as unknown as string)).toBeUndefined()
    expect(decodePgp(42 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for empty / whitespace-only input', () => {
    expect(decodePgp('')).toBeUndefined()
    expect(decodePgp('   ')).toBeUndefined()
  })

  it('returns undefined when no BEGIN marker is present', () => {
    expect(decodePgp('nothing to see here')).toBeUndefined()
  })

  it('returns undefined when the BEGIN and END block types disagree', () => {
    const blob = `-----BEGIN PGP MESSAGE-----\n\nAAAA\n=AAAA\n-----END PGP SIGNATURE-----`
    expect(decodePgp(blob)).toBeUndefined()
  })

  it('returns undefined for an unsupported block type', () => {
    const blob =
      `-----BEGIN PGP ARMORED FILE-----\n\nAAAA\n=AAAA\n-----END PGP ARMORED FILE-----`
    expect(decodePgp(blob)).toBeUndefined()
  })

  it('returns undefined when there is no END marker', () => {
    const blob = `-----BEGIN PGP MESSAGE-----\n\nAAAA\n=AAAA`
    expect(decodePgp(blob)).toBeUndefined()
  })

  it('flags a malformed base64 body by returning no firstPacketTag', () => {
    // Body is not valid base64 — should not crash, just leave the tag
    // undefined so the findings layer can emit pgp.armor.malformed.
    const blob =
      `-----BEGIN PGP MESSAGE-----\n\n@@@not-base64@@@\n=AAAA\n-----END PGP MESSAGE-----`
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('MESSAGE')
    expect(decoded?.firstPacketTag).toBeUndefined()
  })

  it('returns no firstPacketTag for an empty body', () => {
    const blob = `-----BEGIN PGP MESSAGE-----\n\n=AAAA\n-----END PGP MESSAGE-----`
    const decoded = decodePgp(blob)
    expect(decoded?.blockType).toBe('MESSAGE')
    expect(decoded?.firstPacketTag).toBeUndefined()
  })
})
