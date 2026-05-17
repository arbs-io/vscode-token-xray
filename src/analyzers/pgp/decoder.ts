/**
 * Minimal OpenPGP ASCII-armor decoder (RFC 9580 / RFC 4880 §6).
 *
 * An armored block looks like:
 *
 *   -----BEGIN PGP <TYPE>-----
 *   Version: GnuPG v2          ← optional `Key: Value` lines
 *   Comment: …                   (zero or more, blank line terminates)
 *
 *   <base64 body, possibly wrapped>
 *   =<4-char base64 CRC24>     ← optional checksum line
 *   -----END PGP <TYPE>-----
 *
 * We do NOT attempt a full packet parse — only enough to surface block
 * type, the optional Version/Comment headers, and the first packet's
 * tag byte (RFC 4880 §4.2: bit 7 is always 1; bit 6 toggles new-format).
 *
 * Cleartext-signed messages (`SIGNED MESSAGE`) interleave the cleartext
 * with a `-----BEGIN PGP SIGNATURE-----` block; our decoder simply
 * returns `firstPacketTag === undefined` for that variant because the
 * body before the inner signature isn't base64.
 *
 * No vscode imports — pure TS so tests can run under Vitest.
 */

export type PgpBlockType =
  | 'PUBLIC KEY BLOCK'
  | 'PRIVATE KEY BLOCK'
  | 'SIGNATURE'
  | 'MESSAGE'
  | 'SIGNED MESSAGE'

const SUPPORTED_BLOCK_TYPES: ReadonlySet<string> = new Set<PgpBlockType>([
  'PUBLIC KEY BLOCK',
  'PRIVATE KEY BLOCK',
  'SIGNATURE',
  'MESSAGE',
  'SIGNED MESSAGE',
])

export interface DecodedPgp {
  /** The armored block type, exactly as it appears between the dashes. */
  blockType: PgpBlockType
  /** Any optional `Key: Value` header lines that preceded the blank line. */
  headers: Record<string, string>
  /**
   * First byte of the base64-decoded body — the OpenPGP packet tag. We
   * only set this when the body looks like base64 and decodes to at
   * least one byte. Cleartext-signed messages and malformed bodies
   * leave this undefined.
   */
  firstPacketTag?: number
}

/**
 * Parse a single armored PGP block. Returns `undefined` on any of:
 *
 *   - non-string / empty input
 *   - missing or mismatched BEGIN/END markers
 *   - unsupported / unknown block type
 *
 * A malformed body (bad base64, no decodable byte) still returns a
 * `DecodedPgp` — the analyzer surfaces that as a finding rather than
 * dropping the match entirely, so users still see "type=PRIVATE KEY
 * BLOCK" when the body has been mangled.
 */
export function decodePgp(blob: string): DecodedPgp | undefined {
  if (typeof blob !== 'string') return undefined
  const trimmed = blob.trim()
  if (trimmed.length === 0) return undefined

  const beginMatch = /-----BEGIN PGP ([A-Z ]+)-----/.exec(trimmed)
  if (!beginMatch) return undefined
  const blockType = beginMatch[1]
  if (!SUPPORTED_BLOCK_TYPES.has(blockType)) return undefined

  const endRegex = new RegExp(`-----END PGP ${escapeRegex(blockType)}-----`)
  const endMatch = endRegex.exec(trimmed)
  if (!endMatch) return undefined
  if (endMatch.index <= beginMatch.index + beginMatch[0].length) return undefined

  const inner = trimmed.slice(beginMatch.index + beginMatch[0].length, endMatch.index)
  const { headers, body } = splitHeadersAndBody(inner)

  const result: DecodedPgp = {
    blockType: blockType as PgpBlockType,
    headers,
  }

  // Cleartext-signed messages don't have a base64 body up front — the
  // first packet (the inner SIGNATURE block) is armored separately.
  if (blockType === 'SIGNED MESSAGE') {
    return result
  }

  const tag = decodeFirstPacketTag(body)
  if (tag !== undefined) result.firstPacketTag = tag
  return result
}

/* ------------------------------------------------------------------ *
 *  Helpers
 * ------------------------------------------------------------------ */

/**
 * Split the inner block (between BEGIN and END markers) into the
 * armor headers (a map of `Key: Value` lines) and the base64 body.
 *
 * Per RFC 9580 §6.2 the headers are terminated by an empty line; any
 * line we can't parse as `Key: Value` ends the header section and
 * starts being treated as body. The body is returned with all
 * whitespace and the optional `=CRC24` line stripped — what's left
 * should be pure base64.
 */
function splitHeadersAndBody(inner: string): {
  headers: Record<string, string>
  body: string
} {
  const headers: Record<string, string> = {}
  const lines = inner.split(/\r?\n/)

  let i = 0
  // Skip the leading newline(s) after the BEGIN marker.
  while (i < lines.length && lines[i].trim().length === 0) i++

  // Optional header block: `Key: Value` lines terminated by a blank line.
  while (i < lines.length) {
    const line = lines[i]
    if (line.trim().length === 0) {
      i++
      break
    }
    const m = /^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$/.exec(line)
    if (!m) {
      // First non-header line — bail out and treat everything from here
      // on as body. This covers the (rare) case of an armored block
      // with no headers at all.
      break
    }
    headers[m[1]] = m[2].trim()
    i++
  }

  // Remaining lines are the base64 body + optional `=CRC24` line.
  let body = ''
  for (; i < lines.length; i++) {
    const raw = lines[i]
    const stripped = raw.trim()
    if (stripped.length === 0) continue
    // The CRC24 line starts with `=` and is exactly 5 chars (`=XXXX`)
    // — strip it. Anything else is body.
    if (stripped.length === 5 && stripped.startsWith('=')) continue
    body += stripped
  }

  return { headers, body }
}

/**
 * Base64-decode the body and return the first byte (the OpenPGP packet
 * tag, RFC 4880 §4.2). Returns `undefined` when the body is empty or
 * the base64 won't decode.
 */
function decodeFirstPacketTag(body: string): number | undefined {
  if (body.length === 0) return undefined
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return undefined
  const bytes = base64ToBytes(body)
  if (!bytes || bytes.length === 0) return undefined
  return bytes[0]
}

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

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`)
}
