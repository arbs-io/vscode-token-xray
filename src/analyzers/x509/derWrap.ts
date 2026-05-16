/**
 * Helpers for detecting base64-DER-encoded x509 certificates (no PEM armor).
 *
 * These are common in `.cer` / `.crt` / `.der` files exported from Windows and
 * other tools. The strategy: validate the text is one continuous base64 blob
 * that decodes to an ASN.1 SEQUENCE long-form (`30 82 LL LL ...`) whose
 * declared length matches the remaining bytes, then wrap the body in standard
 * PEM armor so the existing `decodeX509` decoder can ingest it unchanged.
 *
 * No vscode imports — pure TS so the analyzer remains testable under Vitest.
 */

/** Filename suffixes that strongly suggest base64-DER content. */
const DER_FILENAME_RE = /\.(cer|crt|der)$/i

/** Minimum base64 length we'll consider for unlabelled (filename-less) input.
 *  A useful x509 cert is at least a few hundred bytes of DER ≈ a few hundred
 *  base64 chars. We require ≥1000 chars to avoid matching short blobs that
 *  happen to start with `MII…`. */
const MIN_UNLABELLED_BASE64_LEN = 1000

/** Base64 alphabet (RFC 4648), no whitespace tolerated. */
const STRICT_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/

/**
 * If `text` looks like base64-DER of an x509 certificate, return the
 * canonical PEM-armored equivalent. Otherwise return `undefined`.
 *
 * Heuristic:
 *  - text must NOT already contain PEM armor (`-----BEGIN`).
 *  - text (after stripping whitespace) must be one continuous base64 string.
 *  - the filename hint must end in `.cer` / `.crt` / `.der` (case-insensitive)
 *    OR the stripped base64 must be at least 1000 chars long.
 *  - decoded bytes start with `30 82 LL LL` (DER SEQUENCE long-form, 2 length
 *    bytes), and `LL LL` + 4 header bytes equals the decoded buffer length.
 */
export function tryWrapDerAsPem(text: string, filename?: string): string | undefined {
  if (!text) return undefined
  if (text.includes('-----BEGIN')) return undefined

  const stripped = text.replace(/\s+/g, '')
  if (stripped.length === 0) return undefined
  if (!STRICT_BASE64_RE.test(stripped)) return undefined

  const hasDerSuffix = filename ? DER_FILENAME_RE.test(filename) : false
  if (!hasDerSuffix && stripped.length < MIN_UNLABELLED_BASE64_LEN) return undefined

  // Base64 length must be a multiple of 4 to decode cleanly.
  if (stripped.length % 4 !== 0) return undefined

  let bytes: Buffer
  try {
    bytes = Buffer.from(stripped, 'base64')
  } catch {
    return undefined
  }
  if (bytes.length < 4) return undefined

  // DER SEQUENCE long-form, 2-byte length: 30 82 LL LL.
  // We require exactly the 2-byte long form because legitimate x509 certs are
  // never short enough for short-form (< 128 bytes) nor large enough to need
  // 3+ length bytes for a single cert blob.
  if (bytes[0] !== 0x30 || bytes[1] !== 0x82) return undefined
  const declaredLength = (bytes[2] << 8) | bytes[3]
  if (declaredLength + 4 !== bytes.length) return undefined

  return wrapAsPem(stripped)
}

/** Wrap a (validated) base64 body in standard `BEGIN CERTIFICATE` PEM armor.
 *  The body is broken into 64-char lines as per RFC 7468. */
function wrapAsPem(base64Body: string): string {
  const lines: string[] = []
  for (let i = 0; i < base64Body.length; i += 64) {
    lines.push(base64Body.slice(i, i + 64))
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`
}
