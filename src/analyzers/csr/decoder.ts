/**
 * Minimal CSR (Certificate Signing Request) ASN.1 decoder.
 *
 * Node's `crypto.X509Certificate` only parses certificates, not CSRs, so this
 * file implements a small DER walker against PKCS#10 RFC 2986:
 *
 *   CertificationRequest ::= SEQUENCE {
 *       certificationRequestInfo  CertificationRequestInfo,
 *       signatureAlgorithm        AlgorithmIdentifier,
 *       signature                 BIT STRING
 *   }
 *
 *   CertificationRequestInfo ::= SEQUENCE {
 *       version       INTEGER,
 *       subject       Name,
 *       subjectPKInfo SubjectPublicKeyInfo,
 *       attributes    [0] IMPLICIT Attributes
 *   }
 *
 * The walker is strict-but-small: anything malformed (truncated lengths,
 * mismatched tags, missing required fields) causes `decodeCsr` to return
 * `undefined` so callers can surface a `csr.parse.failed` finding.
 */

export interface DecodedCsr {
  /** Distinguished Name rendered in OpenSSL-ish `CN=foo, O=bar` style. */
  subject: string
  /** Public-key algorithm — `rsa`, `ec`, `ed25519`, `ed448`, or `unknown`. */
  keyAlgorithm: string
  /** RSA modulus bit length (significant bits), or `undefined` for non-RSA. */
  keyBits?: number
  /** EC named curve when `keyAlgorithm === 'ec'`. */
  curve?: string
  /** Requested Subject Alternative Names (DNS / IP / URI / email / dirName). */
  subjectAltNames: string[]
}

interface Tlv {
  tag: number
  length: number
  /** Offset of the first content byte inside the buffer. */
  contentStart: number
  /** Offset one past the last content byte. */
  contentEnd: number
}

const PEM_HEADER = '-----BEGIN CERTIFICATE REQUEST-----'
const PEM_FOOTER = '-----END CERTIFICATE REQUEST-----'

// Tag constants (universal class).
const TAG_INTEGER = 0x02
const TAG_BIT_STRING = 0x03
const TAG_OCTET_STRING = 0x04
const TAG_NULL = 0x05
const TAG_OID = 0x06
const TAG_UTF8_STRING = 0x0c
const TAG_PRINTABLE_STRING = 0x13
const TAG_IA5_STRING = 0x16
const TAG_BMP_STRING = 0x1e
const TAG_SEQUENCE = 0x30
const TAG_SET = 0x31

// Context-specific [0] constructed (used for attributes / [0] EXPLICIT EC params).
const TAG_CTX0_CONSTRUCTED = 0xa0

// OIDs we care about.
const OID_RSA = '1.2.840.113549.1.1.1'
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
const OID_ED25519 = '1.3.101.112'
const OID_ED448 = '1.3.101.113'
const OID_EXTENSION_REQUEST = '1.2.840.113549.1.9.14'
const OID_SUBJECT_ALT_NAME = '2.5.29.17'

// Named curve OIDs (small allowlist — extend if needed).
const NAMED_CURVE: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
  '1.3.132.0.10': 'secp256k1',
}

// Attribute-type OIDs for Subject Name RDNs.
const NAME_ATTR_LABEL: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC',
}

/**
 * Decode a PEM-armored `CERTIFICATE REQUEST` block and extract the subject,
 * public-key algorithm/size, and requested Subject Alternative Names.
 *
 * Returns `undefined` on any of:
 *   - missing PEM armor / non-base64 body / empty body
 *   - truncated DER (length runs past end of buffer)
 *   - tag mismatches at any of the structural positions we care about
 *   - subject decoded to zero RDNs
 *   - SubjectPublicKeyInfo OID not recognised
 */
export function decodeCsr(pem: string): DecodedCsr | undefined {
  if (typeof pem !== 'string') return undefined
  const der = pemToDer(pem)
  if (!der) return undefined

  try {
    return walkCsr(der)
  } catch {
    return undefined
  }
}

/**
 * Locate `-----BEGIN CERTIFICATE REQUEST-----` blocks in arbitrary text.
 *
 * Returns the full PEM span (including armor) plus byte offsets so the
 * analyzer can build a `Match.range`.
 */
const PEM_BLOCK_REGEX = /-----BEGIN CERTIFICATE REQUEST-----[\s\S]*?-----END CERTIFICATE REQUEST-----/g

export function extractCsrBlocks(text: string): Array<{ pem: string; start: number; end: number }> {
  const out: Array<{ pem: string; start: number; end: number }> = []
  if (!text) return out
  PEM_BLOCK_REGEX.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = PEM_BLOCK_REGEX.exec(text)) !== null) {
    out.push({ pem: m[0], start: m.index, end: m.index + m[0].length })
  }
  return out
}

/** Strip the PEM armor and base64-decode the body into a Uint8Array. */
function pemToDer(pem: string): Uint8Array | undefined {
  const start = pem.indexOf(PEM_HEADER)
  const end = pem.indexOf(PEM_FOOTER)
  if (start < 0 || end < 0 || end < start) return undefined
  const body = pem.slice(start + PEM_HEADER.length, end).replace(/\s+/g, '')
  if (body.length === 0) return undefined
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) return undefined
  try {
    const binary = atob(body)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.codePointAt(i) ?? 0
    return bytes
  } catch {
    return undefined
  }
}

/* ------------------------------------------------------------------ *
 *  Core walker
 * ------------------------------------------------------------------ */

function walkCsr(der: Uint8Array): DecodedCsr | undefined {
  // CertificationRequest SEQUENCE
  const outer = readTlv(der, 0)
  if (outer.tag !== TAG_SEQUENCE) return undefined

  // CertificationRequestInfo SEQUENCE (first child of the outer SEQUENCE).
  const cri = readTlv(der, outer.contentStart)
  if (cri.tag !== TAG_SEQUENCE) return undefined

  let cursor = cri.contentStart

  // version INTEGER
  const version = readTlv(der, cursor)
  if (version.tag !== TAG_INTEGER) return undefined
  cursor = version.contentEnd

  // subject Name (SEQUENCE OF RDN SETs)
  const subjectTlv = readTlv(der, cursor)
  if (subjectTlv.tag !== TAG_SEQUENCE) return undefined
  const subject = parseName(der, subjectTlv)
  if (subject.length === 0) return undefined
  cursor = subjectTlv.contentEnd

  // subjectPKInfo SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const spki = readTlv(der, cursor)
  if (spki.tag !== TAG_SEQUENCE) return undefined
  const pk = parsePublicKey(der, spki)
  if (!pk) return undefined
  cursor = spki.contentEnd

  // attributes [0] IMPLICIT — optional
  let subjectAltNames: string[] = []
  if (cursor < cri.contentEnd) {
    const attrs = readTlv(der, cursor)
    if (attrs.tag === TAG_CTX0_CONSTRUCTED) {
      subjectAltNames = parseAttributesForSan(der, attrs)
    }
  }

  return {
    subject,
    keyAlgorithm: pk.algorithm,
    keyBits: pk.bits,
    curve: pk.curve,
    subjectAltNames,
  }
}

/* ------------------------------------------------------------------ *
 *  TLV reader
 * ------------------------------------------------------------------ */

function readTlv(buf: Uint8Array, offset: number): Tlv {
  if (offset >= buf.length) throw new Error('TLV out of bounds')
  const tag = buf[offset]
  let lengthByte = buf[offset + 1]
  if (lengthByte === undefined) throw new Error('Truncated length')
  let length: number
  let contentStart: number
  if ((lengthByte & 0x80) === 0) {
    length = lengthByte
    contentStart = offset + 2
  } else {
    const numLenBytes = lengthByte & 0x7f
    if (numLenBytes === 0 || numLenBytes > 4) throw new Error('Unsupported length form')
    length = 0
    for (let i = 0; i < numLenBytes; i++) {
      const b = buf[offset + 2 + i]
      if (b === undefined) throw new Error('Truncated length bytes')
      length = (length << 8) | b
    }
    contentStart = offset + 2 + numLenBytes
  }
  const contentEnd = contentStart + length
  if (contentEnd > buf.length) throw new Error('TLV runs past buffer end')
  return { tag, length, contentStart, contentEnd }
}

/* ------------------------------------------------------------------ *
 *  Subject Name → "CN=foo, O=bar"
 * ------------------------------------------------------------------ */

function parseName(buf: Uint8Array, name: Tlv): string {
  const parts: string[] = []
  let cursor = name.contentStart
  while (cursor < name.contentEnd) {
    const rdn = readTlv(buf, cursor)
    if (rdn.tag !== TAG_SET) {
      cursor = rdn.contentEnd
      continue
    }
    let inner = rdn.contentStart
    while (inner < rdn.contentEnd) {
      const ava = readTlv(buf, inner)
      if (ava.tag === TAG_SEQUENCE) {
        const oidTlv = readTlv(buf, ava.contentStart)
        if (oidTlv.tag === TAG_OID) {
          const oid = decodeOid(buf, oidTlv)
          const valueTlv = readTlv(buf, oidTlv.contentEnd)
          const value = decodeString(buf, valueTlv)
          if (value !== undefined) {
            const label = NAME_ATTR_LABEL[oid] ?? oid
            parts.push(`${label}=${value}`)
          }
        }
      }
      inner = ava.contentEnd
    }
    cursor = rdn.contentEnd
  }
  return parts.join(', ')
}

/* ------------------------------------------------------------------ *
 *  SubjectPublicKeyInfo
 * ------------------------------------------------------------------ */

interface PublicKeyInfo {
  algorithm: 'rsa' | 'ec' | 'ed25519' | 'ed448' | 'unknown'
  bits?: number
  curve?: string
}

function parsePublicKey(buf: Uint8Array, spki: Tlv): PublicKeyInfo | undefined {
  // SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const alg = readTlv(buf, spki.contentStart)
  if (alg.tag !== TAG_SEQUENCE) return undefined
  const oidTlv = readTlv(buf, alg.contentStart)
  if (oidTlv.tag !== TAG_OID) return undefined
  const algOid = decodeOid(buf, oidTlv)

  // Optional parameters follow the OID inside the AlgorithmIdentifier SEQUENCE.
  let curve: string | undefined
  if (oidTlv.contentEnd < alg.contentEnd) {
    const params = readTlv(buf, oidTlv.contentEnd)
    if (params.tag === TAG_OID) {
      const curveOid = decodeOid(buf, params)
      curve = NAMED_CURVE[curveOid] ?? curveOid
    }
  }

  const bitStr = readTlv(buf, alg.contentEnd)
  if (bitStr.tag !== TAG_BIT_STRING) return undefined

  if (algOid === OID_RSA) {
    const bits = parseRsaModulusBits(buf, bitStr)
    return { algorithm: 'rsa', bits }
  }
  if (algOid === OID_EC_PUBLIC_KEY) {
    return { algorithm: 'ec', curve }
  }
  if (algOid === OID_ED25519) return { algorithm: 'ed25519' }
  if (algOid === OID_ED448) return { algorithm: 'ed448' }
  return { algorithm: 'unknown' }
}

/**
 * Bit length of the RSA modulus (the first INTEGER inside the RSAPublicKey
 * SEQUENCE wrapped in the BIT STRING). The leading 0x00 padding byte that
 * keeps the INTEGER non-negative is skipped, then the first significant bit
 * of the remaining bytes is found.
 */
function parseRsaModulusBits(buf: Uint8Array, bitStr: Tlv): number | undefined {
  // BIT STRING starts with one byte indicating the number of unused bits in
  // the final octet (always 0 for SPKI). Skip it before re-reading as DER.
  const unused = buf[bitStr.contentStart]
  if (unused !== 0) return undefined
  const rsaSeq = readTlv(buf, bitStr.contentStart + 1)
  if (rsaSeq.tag !== TAG_SEQUENCE) return undefined
  const modulus = readTlv(buf, rsaSeq.contentStart)
  if (modulus.tag !== TAG_INTEGER) return undefined
  let start = modulus.contentStart
  // Skip leading 0x00 padding bytes (DER requires at most one for positivity,
  // but be lenient).
  while (start < modulus.contentEnd && buf[start] === 0x00) start++
  if (start >= modulus.contentEnd) return 0
  const firstByte = buf[start]
  let firstBits = 8
  for (let mask = 0x80; mask > 0; mask >>= 1) {
    if (firstByte & mask) break
    firstBits--
  }
  return firstBits + (modulus.contentEnd - start - 1) * 8
}

/* ------------------------------------------------------------------ *
 *  Attributes → SubjectAltName
 * ------------------------------------------------------------------ */

function parseAttributesForSan(buf: Uint8Array, attrs: Tlv): string[] {
  const sans: string[] = []
  let cursor = attrs.contentStart
  while (cursor < attrs.contentEnd) {
    const attr = readTlv(buf, cursor)
    if (attr.tag === TAG_SEQUENCE) {
      const oidTlv = readTlv(buf, attr.contentStart)
      if (oidTlv.tag === TAG_OID) {
        const attrOid = decodeOid(buf, oidTlv)
        if (attrOid === OID_EXTENSION_REQUEST) {
          const setTlv = readTlv(buf, oidTlv.contentEnd)
          if (setTlv.tag === TAG_SET) {
            sans.push(...parseExtensionRequest(buf, setTlv))
          }
        }
      }
    }
    cursor = attr.contentEnd
  }
  return sans
}

function parseExtensionRequest(buf: Uint8Array, set: Tlv): string[] {
  // SET OF { SEQUENCE OF Extension }
  const sans: string[] = []
  let cursor = set.contentStart
  while (cursor < set.contentEnd) {
    const seq = readTlv(buf, cursor)
    if (seq.tag === TAG_SEQUENCE) {
      let extCursor = seq.contentStart
      while (extCursor < seq.contentEnd) {
        const ext = readTlv(buf, extCursor)
        if (ext.tag === TAG_SEQUENCE) {
          const oidTlv = readTlv(buf, ext.contentStart)
          if (oidTlv.tag === TAG_OID) {
            const extOid = decodeOid(buf, oidTlv)
            if (extOid === OID_SUBJECT_ALT_NAME) {
              // The next TLV is either OCTET STRING (DER-encoded SAN) or — if
              // an optional `critical BOOLEAN` is present — a BOOLEAN followed
              // by the OCTET STRING. Walk forward looking for the OCTET STRING.
              let inner = oidTlv.contentEnd
              while (inner < ext.contentEnd) {
                const t = readTlv(buf, inner)
                if (t.tag === TAG_OCTET_STRING) {
                  const sanSeq = readTlv(buf, t.contentStart)
                  if (sanSeq.tag === TAG_SEQUENCE) {
                    sans.push(...parseSanNames(buf, sanSeq))
                  }
                  break
                }
                inner = t.contentEnd
              }
            }
          }
        }
        extCursor = ext.contentEnd
      }
    }
    cursor = seq.contentEnd
  }
  return sans
}

/**
 * GeneralName ::= CHOICE { rfc822Name [1] IA5String, dNSName [2] IA5String,
 *   uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING, ... }
 *
 * Each appears as a context-specific tag in the outer SAN SEQUENCE.
 */
function parseSanNames(buf: Uint8Array, sanSeq: Tlv): string[] {
  const out: string[] = []
  let cursor = sanSeq.contentStart
  while (cursor < sanSeq.contentEnd) {
    const name = readTlv(buf, cursor)
    const tagNumber = name.tag & 0x1f
    const slice = buf.slice(name.contentStart, name.contentEnd)
    if (tagNumber === 1) out.push(`email:${bytesToAscii(slice)}`)
    else if (tagNumber === 2) out.push(`DNS:${bytesToAscii(slice)}`)
    else if (tagNumber === 6) out.push(`URI:${bytesToAscii(slice)}`)
    else if (tagNumber === 7) out.push(`IP:${formatIp(slice)}`)
    cursor = name.contentEnd
  }
  return out
}

/* ------------------------------------------------------------------ *
 *  OID / string / IP helpers
 * ------------------------------------------------------------------ */

function decodeOid(buf: Uint8Array, oid: Tlv): string {
  const parts: number[] = []
  let value = 0
  for (let i = oid.contentStart; i < oid.contentEnd; i++) {
    const b = buf[i]
    value = (value << 7) | (b & 0x7f)
    if ((b & 0x80) === 0) {
      if (parts.length === 0) {
        const first = Math.min(2, Math.floor(value / 40))
        parts.push(first, value - first * 40)
      } else {
        parts.push(value)
      }
      value = 0
    }
  }
  return parts.join('.')
}

function decodeString(buf: Uint8Array, tlv: Tlv): string | undefined {
  const slice = buf.slice(tlv.contentStart, tlv.contentEnd)
  switch (tlv.tag) {
    case TAG_UTF8_STRING:
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(slice)
      } catch {
        return undefined
      }
    case TAG_PRINTABLE_STRING:
    case TAG_IA5_STRING:
      return bytesToAscii(slice)
    case TAG_BMP_STRING: {
      // UTF-16BE
      if (slice.length % 2 !== 0) return undefined
      let out = ''
      for (let i = 0; i < slice.length; i += 2) {
        out += String.fromCodePoint((slice[i] << 8) | slice[i + 1])
      }
      return out
    }
    default:
      return undefined
  }
}

function bytesToAscii(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCodePoint(b)
  return s
}

function formatIp(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join('.')
  if (bytes.length === 16) {
    const parts: string[] = []
    for (let i = 0; i < 16; i += 2) {
      parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16))
    }
    return parts.join(':')
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
