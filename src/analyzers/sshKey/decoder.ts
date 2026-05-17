/**
 * Minimal OpenSSH public-key wire-format decoder.
 *
 * RFC 4253 §6.6 / RFC 4716. A public key line looks like:
 *
 *   <type> <base64-body> [comment]
 *
 * where the base64 body decodes to a sequence of length-prefixed fields.
 * Each field is encoded as:
 *
 *   uint32-BE length || length bytes
 *
 * The first field is always a `string` containing the algorithm name,
 * which must match the `<type>` prefix on the line — a mismatch is the
 * single most reliable indicator that the line isn't actually an SSH
 * public key, so we use it as our base validation check.
 *
 * No vscode imports — pure TS so the analyzer remains testable under
 * Vitest.
 */

/**
 * One of the supported OpenSSH public-key algorithm identifiers. We keep
 * the strings exactly as they appear on the wire.
 */
export type SshKeyType =
  | 'ssh-rsa'
  | 'ssh-ed25519'
  | 'ssh-dss'
  | 'ecdsa-sha2-nistp256'
  | 'ecdsa-sha2-nistp384'
  | 'ecdsa-sha2-nistp521'

const SUPPORTED_TYPES: ReadonlySet<string> = new Set<SshKeyType>([
  'ssh-rsa',
  'ssh-ed25519',
  'ssh-dss',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
])

/** ECDSA curve identifier that follows the algorithm name on the wire. */
const ECDSA_CURVE_FOR: Record<string, 'nistp256' | 'nistp384' | 'nistp521'> = {
  'ecdsa-sha2-nistp256': 'nistp256',
  'ecdsa-sha2-nistp384': 'nistp384',
  'ecdsa-sha2-nistp521': 'nistp521',
}

export interface DecodedSshKey {
  /** Algorithm identifier exactly as it appears on the wire. */
  type: SshKeyType
  /** Optional comment trailing the base64 body. */
  comment?: string
  /** Significant-bit length of the RSA modulus, if this is an RSA key. */
  modulusBits?: number
  /** ECDSA curve identifier (e.g. `nistp256`), if this is an ECDSA key. */
  curve?: 'nistp256' | 'nistp384' | 'nistp521'
}

/**
 * Parse a single OpenSSH public-key line. Returns `undefined` on any of:
 *
 *   - non-string / empty input
 *   - unrecognised algorithm prefix
 *   - malformed base64 body
 *   - truncated / oversized length-prefixed fields
 *   - the algorithm string embedded in the body disagrees with the prefix
 *
 * The function intentionally does NOT throw — callers (the analyzer
 * detect path in particular) need an idiomatic Optional to filter out
 * lines that merely look like SSH keys but aren't.
 */
interface ParsedLine {
  type: string
  body: string
  comment?: string
}

function parseSshKeyLine(line: string): ParsedLine | undefined {
  if (typeof line !== 'string') return undefined
  const trimmed = line.trim()
  if (trimmed.length === 0) return undefined

  // Split into at most three tokens: type, base64-body, optional comment.
  const firstSpace = trimmed.indexOf(' ')
  if (firstSpace <= 0) return undefined
  const type = trimmed.slice(0, firstSpace)
  if (!SUPPORTED_TYPES.has(type)) return undefined

  const rest = trimmed.slice(firstSpace + 1).trimStart()
  const secondSpace = rest.indexOf(' ')
  const body = secondSpace === -1 ? rest : rest.slice(0, secondSpace)
  const comment = secondSpace === -1 ? undefined : rest.slice(secondSpace + 1).trim()

  if (body.length === 0) return undefined
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return undefined
  return { type, body, comment }
}

function decodeByType(type: string, reader: WireReader, base: DecodedSshKey): DecodedSshKey | undefined {
  switch (type) {
    case 'ssh-rsa': {
      const e = reader.readBytes()
      const n = reader.readBytes()
      if (!e || !n) return undefined
      return { ...base, modulusBits: significantBitLength(n) }
    }
    case 'ssh-ed25519': {
      const pub = reader.readBytes()
      if (pub?.length !== 32) return undefined
      return base
    }
    case 'ecdsa-sha2-nistp256':
    case 'ecdsa-sha2-nistp384':
    case 'ecdsa-sha2-nistp521': {
      const curve = reader.readString()
      const expected = ECDSA_CURVE_FOR[type]
      if (curve !== expected) return undefined
      const point = reader.readBytes()
      if (!point || point.length === 0) return undefined
      return { ...base, curve: expected }
    }
    case 'ssh-dss': {
      // ssh-dss: p, q, g, y. We don't need the values — the algorithm
      // itself is weak so we just confirm the structure is sane.
      const p = reader.readBytes()
      const q = reader.readBytes()
      const g = reader.readBytes()
      const y = reader.readBytes()
      if (!p || !q || !g || !y) return undefined
      return base
    }
    default:
      return undefined
  }
}

export function decodeSshKey(line: string): DecodedSshKey | undefined {
  const parsed = parseSshKeyLine(line)
  if (!parsed) return undefined
  const { type, body, comment } = parsed

  const bytes = base64ToBytes(body)
  if (!bytes) return undefined

  // The first wire field must be the algorithm name and must match the
  // prefix on the line. This is the spec-mandated validation that makes
  // false positives essentially impossible.
  const reader = new WireReader(bytes)
  if (reader.readString() !== type) return undefined

  const base: DecodedSshKey = {
    type: type as SshKeyType,
    ...(comment && comment.length > 0 ? { comment } : {}),
  }
  return decodeByType(type, reader, base)
}

/* ------------------------------------------------------------------ *
 *  Wire-format reader
 * ------------------------------------------------------------------ */

class WireReader {
  private offset = 0
  constructor(private readonly buf: Uint8Array) {}

  readBytes(): Uint8Array | undefined {
    if (this.offset + 4 > this.buf.length) return undefined
    const length =
      (this.buf[this.offset] << 24) |
      (this.buf[this.offset + 1] << 16) |
      (this.buf[this.offset + 2] << 8) |
      this.buf[this.offset + 3]
    // Reject negative (>= 2^31) and oversized lengths.
    if (length < 0) return undefined
    if (this.offset + 4 + length > this.buf.length) return undefined
    const out = this.buf.slice(this.offset + 4, this.offset + 4 + length)
    this.offset += 4 + length
    return out
  }

  readString(): string | undefined {
    const bytes = this.readBytes()
    if (!bytes) return undefined
    return bytesToAscii(bytes)
  }
}

/* ------------------------------------------------------------------ *
 *  Helpers
 * ------------------------------------------------------------------ */

function base64ToBytes(body: string): Uint8Array | undefined {
  try {
    const binary = atob(body)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.codePointAt(i) ?? 0
    return bytes
  } catch {
    return undefined
  }
}

function bytesToAscii(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCodePoint(b)
  return s
}

/**
 * Significant-bit length of an unsigned big-endian integer encoded with
 * the leading 0x00 padding byte the SSH `mpint` representation uses to
 * keep the value non-negative. The padding byte is skipped, then the
 * position of the first set bit in the remaining bytes is found.
 */
function significantBitLength(bytes: Uint8Array): number {
  let start = 0
  while (start < bytes.length && bytes[start] === 0x00) start++
  if (start >= bytes.length) return 0
  const firstByte = bytes[start]
  let firstBits = 8
  for (let mask = 0x80; mask > 0; mask >>= 1) {
    if (firstByte & mask) break
    firstBits--
  }
  return firstBits + (bytes.length - start - 1) * 8
}
