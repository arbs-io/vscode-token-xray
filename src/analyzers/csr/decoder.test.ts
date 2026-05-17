import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeCsr, extractCsrBlocks } from './decoder'

const FIX_DIR = join(__dirname, 'fixtures')
const pem = (name: string): string => readFileSync(join(FIX_DIR, name), 'utf8')

describe('extractCsrBlocks', () => {
  it('finds a single CSR PEM block', () => {
    const blocks = extractCsrBlocks(pem('good.pem'))
    expect(blocks).toHaveLength(1)
    expect(blocks[0].start).toBe(0)
    expect(blocks[0].pem).toContain('-----BEGIN CERTIFICATE REQUEST-----')
    expect(blocks[0].pem).toContain('-----END CERTIFICATE REQUEST-----')
  })

  it('finds multiple CSR blocks in a wider document', () => {
    const text = `${pem('good.pem')}\nfiller text\n${pem('weak-key.pem')}`
    expect(extractCsrBlocks(text)).toHaveLength(2)
  })

  it('returns empty for input without a CSR block', () => {
    expect(extractCsrBlocks('no csr here')).toEqual([])
  })

  it('returns empty for empty input', () => {
    expect(extractCsrBlocks('')).toEqual([])
  })

  it('does not match a CERTIFICATE (not REQUEST) PEM block', () => {
    expect(
      extractCsrBlocks('-----BEGIN CERTIFICATE-----\nMIIBkTCCAToCAQAwIzELMAkGA1UE\n-----END CERTIFICATE-----')
    ).toEqual([])
  })
})

describe('decodeCsr', () => {
  it('decodes a healthy RSA-2048 CSR with SANs', () => {
    const decoded = decodeCsr(pem('good.pem'))
    expect(decoded).toBeDefined()
    expect(decoded?.subject).toContain('CN=good.example.test')
    expect(decoded?.subject).toContain('O=Example Org')
    expect(decoded?.keyAlgorithm).toBe('rsa')
    expect(decoded?.keyBits).toBe(2048)
    expect(decoded?.subjectAltNames).toContain('DNS:good.example.test')
    expect(decoded?.subjectAltNames).toContain('DNS:www.example.test')
  })

  it('detects RSA-1024 key size', () => {
    const decoded = decodeCsr(pem('weak-key.pem'))
    expect(decoded?.keyAlgorithm).toBe('rsa')
    expect(decoded?.keyBits).toBe(1024)
  })

  it('returns subjectAltNames=[] when no SAN extension was requested', () => {
    const decoded = decodeCsr(pem('no-san.pem'))
    expect(decoded?.subject).toContain('CN=nosan.example.test')
    expect(decoded?.subjectAltNames).toEqual([])
  })

  it('decodes an EC P-256 CSR with diverse SAN entries', () => {
    const decoded = decodeCsr(pem('ec.pem'))
    expect(decoded).toBeDefined()
    expect(decoded?.keyAlgorithm).toBe('ec')
    expect(decoded?.curve).toBe('P-256')
    // RSA-specific keyBits should be absent for EC.
    expect(decoded?.keyBits).toBeUndefined()
    // Subject covers a six-attribute DN including emailAddress (an
    // IA5String value, which exercises a different decodeString branch
    // from the UTF8String labels above).
    expect(decoded?.subject).toContain('CN=ec.example.test')
    expect(decoded?.subject).toContain('C=US')
    expect(decoded?.subject).toContain('emailAddress=ops@example.test')
    // SAN GeneralName CHOICE coverage: DNS / IP (v4 + v6) / URI / email.
    expect(decoded?.subjectAltNames).toContain('DNS:ec.example.test')
    expect(decoded?.subjectAltNames).toContain('IP:192.168.1.1')
    expect(decoded?.subjectAltNames?.find((s) => s.startsWith('IP:') && s.includes(':'))).toBeDefined()
    expect(decoded?.subjectAltNames).toContain('URI:https://ec.example.test/')
    expect(decoded?.subjectAltNames).toContain('email:ops@example.test')
  })

  it('returns undefined for non-string input', () => {
    expect(decodeCsr(undefined as unknown as string)).toBeUndefined()
    expect(decodeCsr(123 as unknown as string)).toBeUndefined()
  })

  it('returns undefined for missing PEM armor', () => {
    expect(decodeCsr('not a CSR')).toBeUndefined()
  })

  it('returns undefined for an empty PEM body', () => {
    expect(decodeCsr('-----BEGIN CERTIFICATE REQUEST-----\n\n-----END CERTIFICATE REQUEST-----')).toBeUndefined()
  })

  it('returns undefined for an invalid base64 PEM body', () => {
    expect(
      decodeCsr('-----BEGIN CERTIFICATE REQUEST-----\n!!not-base64!!\n-----END CERTIFICATE REQUEST-----')
    ).toBeUndefined()
  })

  it('returns undefined for a truncated DER payload', () => {
    // Valid base64 ("MIIB" decodes to SEQUENCE with claimed length) but no body.
    expect(
      decodeCsr('-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----')
    ).toBeUndefined()
  })

  it('returns undefined for arbitrary random base64', () => {
    // 32 bytes of arbitrary base64 — decodes but is not a SEQUENCE.
    expect(
      decodeCsr(
        '-----BEGIN CERTIFICATE REQUEST-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2\n-----END CERTIFICATE REQUEST-----'
      )
    ).toBeUndefined()
  })

  it('returns undefined when END footer is missing', () => {
    expect(decodeCsr('-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n')).toBeUndefined()
  })

  it('returns undefined when BEGIN header is missing', () => {
    expect(decodeCsr('MIIB\n-----END CERTIFICATE REQUEST-----')).toBeUndefined()
  })

  it('returns undefined when END footer precedes BEGIN header', () => {
    const swapped = '-----END CERTIFICATE REQUEST-----\nMIIB\n-----BEGIN CERTIFICATE REQUEST-----'
    expect(decodeCsr(swapped)).toBeUndefined()
  })
})

/**
 * Helpers that re-encode a known-good CSR with targeted byte mutations so we
 * can exercise the negative branches of the ASN.1 walker without having to
 * synthesise a full PKCS#10 from scratch.
 *
 * Each test extracts the DER body, flips a single tag at a structural
 * position the walker checks, then re-wraps the body in PEM armor.
 */
function derFromPem(p: string): Uint8Array {
  const m = /-----BEGIN CERTIFICATE REQUEST-----([\s\S]*?)-----END CERTIFICATE REQUEST-----/.exec(p)
  if (!m) throw new Error('PEM not found')
  const body = m[1].replace(/\s+/g, '')
  const binary = atob(body)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.codePointAt(i) ?? 0
  return bytes
}

function pemFromDer(der: Uint8Array): string {
  let b = ''
  for (const byte of der) b += String.fromCodePoint(byte)
  const base64 = btoa(b)
  const wrapped = base64.replace(/(.{64})/g, '$1\n')
  return `-----BEGIN CERTIFICATE REQUEST-----\n${wrapped}\n-----END CERTIFICATE REQUEST-----`
}

describe('decodeCsr — DER mutation negatives', () => {
  const goodDer = derFromPem(pem('good.pem'))

  function mutate(offset: number, byte: number): string {
    const copy = goodDer.slice()
    copy[offset] = byte
    return pemFromDer(copy)
  }

  it('returns undefined when outer SEQUENCE tag is wrong', () => {
    // Replace 0x30 (SEQUENCE) at offset 0 with 0x31 (SET).
    expect(decodeCsr(mutate(0, 0x31))).toBeUndefined()
  })

  it('returns undefined when CertificationRequestInfo tag is wrong', () => {
    // Find the inner SEQUENCE tag after the outer length bytes. For our
    // 1021-byte good.pem, offset 0 is 0x30, offset 1 is 0x82 (multi-byte
    // length), then two length bytes, then the inner 0x30.
    expect(decodeCsr(mutate(4, 0x31))).toBeUndefined()
  })
})
