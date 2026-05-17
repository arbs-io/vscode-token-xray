import { describe, expect, it } from 'vitest'
import { PgpAnalyzer } from './analyzer'

/* ------------------------------------------------------------------ *
 *  Synthesis helpers (mirrors decoder.test.ts but kept local so each
 *  test file is self-contained).
 * ------------------------------------------------------------------ */

function bytesToBase64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCodePoint(b)
  return btoa(s)
}

function armor(blockType: string, tag: number, headers?: Record<string, string>): string {
  const body = bytesToBase64(new Uint8Array([tag, 0x01, 0x02]))
  const headerLines = headers
    ? Object.entries(headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n') + '\n'
    : ''
  return (
    `-----BEGIN PGP ${blockType}-----\n` +
    headerLines +
    `\n` +
    body +
    `\n=AAAA\n` +
    `-----END PGP ${blockType}-----`
  )
}

const SIGNED_MESSAGE =
  `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello world.\n-----END PGP SIGNED MESSAGE-----`

/* ------------------------------------------------------------------ *
 *  Tests
 * ------------------------------------------------------------------ */

describe('PgpAnalyzer', () => {
  const analyzer = new PgpAnalyzer()

  it('exposes id "pgp" and a human name', () => {
    expect(analyzer.id).toBe('pgp')
    expect(analyzer.name).toBe('OpenPGP armored block')
  })

  it('detects a PUBLIC KEY BLOCK with byte range', () => {
    const text = armor('PUBLIC KEY BLOCK', 0xc6)
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(1)
    expect(matches[0].range?.start).toBe(0)
    expect(matches[0].range?.end).toBe(text.length)
    expect(matches[0].text).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----')
  })

  it('detects all supported block types', () => {
    expect(analyzer.detect(armor('PUBLIC KEY BLOCK', 0xc6))).toHaveLength(1)
    expect(analyzer.detect(armor('PRIVATE KEY BLOCK', 0xc5))).toHaveLength(1)
    expect(analyzer.detect(armor('SIGNATURE', 0xc2))).toHaveLength(1)
    expect(analyzer.detect(armor('MESSAGE', 0xc1))).toHaveLength(1)
    expect(analyzer.detect(SIGNED_MESSAGE)).toHaveLength(1)
  })

  it('returns empty for unrelated text', () => {
    expect(analyzer.detect('')).toEqual([])
    expect(analyzer.detect('no pgp here')).toEqual([])
  })

  it('skips blocks whose BEGIN and END markers disagree', () => {
    const blob =
      `-----BEGIN PGP MESSAGE-----\n\nAAAA\n=AAAA\n-----END PGP SIGNATURE-----`
    expect(analyzer.detect(blob)).toEqual([])
  })

  it('finds multiple stacked blocks in one document', () => {
    const text = `${armor('PUBLIC KEY BLOCK', 0xc6)}\nfiller\n${armor('SIGNATURE', 0xc2)}`
    const matches = analyzer.detect(text)
    expect(matches).toHaveLength(2)
  })

  it('analyse exposes blockType row and packet tag in hex', () => {
    const [m] = analyzer.detect(armor('PUBLIC KEY BLOCK', 0xc6))
    const result = analyzer.analyze(m)
    expect(result.analyzerId).toBe('pgp')
    expect(result.kind).toBe('OpenPGP public key')
    expect(result.sections).toHaveLength(1)
    expect(result.sections[0].id).toBe('block')
    expect(result.sections[0].title).toBe('Block')
    const rows = result.sections[0].rows
    expect(rows.find((r) => r.key === 'blockType')?.value).toBe('PUBLIC KEY BLOCK')
    expect(rows.find((r) => r.key === 'firstPacketTag')?.value).toBe('0xC6')
  })

  it('analyse surfaces version and comment rows from headers', () => {
    const blob = armor('PUBLIC KEY BLOCK', 0xc6, {
      Version: 'GnuPG v2.4.0',
      Comment: 'example@host',
    })
    const [m] = analyzer.detect(blob)
    const result = analyzer.analyze(m)
    const rows = result.sections[0].rows
    expect(rows.find((r) => r.key === 'version')?.value).toBe('GnuPG v2.4.0')
    expect(rows.find((r) => r.key === 'comment')?.value).toBe('example@host')
  })

  it('analyse omits version/comment rows when headers are absent', () => {
    const [m] = analyzer.detect(armor('PUBLIC KEY BLOCK', 0xc6))
    const result = analyzer.analyze(m)
    const rows = result.sections[0].rows
    expect(rows.find((r) => r.key === 'version')).toBeUndefined()
    expect(rows.find((r) => r.key === 'comment')).toBeUndefined()
  })

  it('analyse emits pgp.privateKey.present (error) for PRIVATE KEY BLOCK', () => {
    const [m] = analyzer.detect(armor('PRIVATE KEY BLOCK', 0xc5))
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('OpenPGP private key')
    expect(result.findings.find((f) => f.id === 'pgp.privateKey.present')?.severity).toBe('error')
  })

  it('analyse emits pgp.message.encrypted (info) for MESSAGE', () => {
    const [m] = analyzer.detect(armor('MESSAGE', 0xc1))
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('OpenPGP encrypted message')
    expect(result.findings.find((f) => f.id === 'pgp.message.encrypted')?.severity).toBe('info')
  })

  it('analyse emits pgp.armor.malformed (warning) when first packet tag has bit 7 = 0', () => {
    // 0x40 has bit 7 clear → malformed packet header.
    const [m] = analyzer.detect(armor('SIGNATURE', 0x40))
    const result = analyzer.analyze(m)
    expect(result.findings.find((f) => f.id === 'pgp.armor.malformed')?.severity).toBe('warning')
  })

  it('analyse emits no findings for a healthy PUBLIC KEY BLOCK', () => {
    const [m] = analyzer.detect(armor('PUBLIC KEY BLOCK', 0xc6))
    const result = analyzer.analyze(m)
    expect(result.findings).toEqual([])
  })

  it('analyse handles SIGNED MESSAGE (cleartext) and reports cleartext-signed kind', () => {
    const [m] = analyzer.detect(SIGNED_MESSAGE)
    const result = analyzer.analyze(m)
    expect(result.kind).toBe('OpenPGP cleartext-signed message')
    // No firstPacketTag row for cleartext-signed.
    expect(result.sections[0].rows.find((r) => r.key === 'firstPacketTag')).toBeUndefined()
    // And no malformed finding for cleartext-signed.
    expect(result.findings.find((f) => f.id === 'pgp.armor.malformed')).toBeUndefined()
  })

  it('analyse throws when handed text that is not a PGP armored block', () => {
    expect(() => analyzer.analyze({ text: 'not a pgp block' })).toThrow(/does not look like/)
  })
})
