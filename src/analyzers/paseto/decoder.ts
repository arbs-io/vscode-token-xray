import { base64UrlDecodeBytes } from '../../core/base64url'

export type PasetoVersion = 'v1' | 'v2' | 'v3' | 'v4'
export type PasetoPurpose = 'local' | 'public'

export interface DecodedPaseto {
  version: PasetoVersion
  purpose: PasetoPurpose
  /** Raw payload segment (base64url, as it appeared in the token). */
  payload: string
  /** Optional footer segment (base64url, as it appeared in the token). */
  footer?: string
  /** Decoded footer string when present and base64url-decodes to printable text. */
  footerDecoded?: string
  /**
   * For `public` purpose: the JSON claims object recovered from the payload
   * (after stripping the signature suffix). Undefined for `local` tokens.
   */
  claims?: Record<string, unknown>
  /**
   * True when the payload looked like a `public` token but the base64url
   * decode or JSON.parse failed. Always false for `local` tokens (their
   * payload is encrypted and never decoded).
   */
  payloadInvalid: boolean
  /** The original input string. */
  raw: string
}

const PASETO_REGEX = /^v([1-4])\.(local|public)\.([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]+))?$/

/** Signature byte length per version for `public` purpose. */
const SIG_BYTES: Record<PasetoVersion, number> = {
  v1: 256, // RSA-PSS 2048-bit
  v2: 64,  // Ed25519
  v3: 96,  // ECDSA P-384 (P1363 raw r||s)
  v4: 64,  // Ed25519
}

/**
 * Cheap shape probe. Used by callers that want to filter input before
 * attempting a full decode.
 */
export function looksLikePaseto(text: string): boolean {
  return PASETO_REGEX.test(text.trim())
}

/**
 * Parse a PASETO string into its components. Returns `undefined` if the
 * input does not match the dot-segmented shape.
 *
 * For `public` tokens, attempts to recover JSON claims by stripping the
 * trailing signature bytes from the decoded payload. If decoding or
 * JSON.parse fails, `claims` is left undefined and `payloadInvalid` is set.
 *
 * For `local` tokens, the payload is encrypted; we record version + purpose
 * and leave `claims` undefined without setting `payloadInvalid`.
 */
export function decodePaseto(token: string): DecodedPaseto | undefined {
  if (typeof token !== 'string' || token.length === 0) return undefined
  const m = PASETO_REGEX.exec(token.trim())
  if (!m) return undefined

  const version = `v${m[1]}` as PasetoVersion
  const purpose = m[2] as PasetoPurpose
  const payload = m[3]
  const footer = m[4]

  const decoded: DecodedPaseto = {
    version,
    purpose,
    payload,
    footer,
    footerDecoded: footer ? tryDecodeFooter(footer) : undefined,
    payloadInvalid: false,
    raw: token,
  }

  if (purpose === 'public') {
    const claims = tryRecoverClaims(payload, version)
    if (claims === 'invalid') {
      decoded.payloadInvalid = true
    } else if (claims !== undefined) {
      decoded.claims = claims
    }
  }

  return decoded
}

function tryRecoverClaims(
  payload: string,
  version: PasetoVersion
): Record<string, unknown> | 'invalid' | undefined {
  let bytes: Uint8Array
  try {
    bytes = base64UrlDecodeBytes(payload)
  } catch {
    return 'invalid'
  }
  const sigLen = SIG_BYTES[version]
  if (bytes.length <= sigLen) {
    // Not enough bytes to even hold a signature → treat as invalid.
    return 'invalid'
  }
  const claimBytes = bytes.subarray(0, bytes.length - sigLen)
  let json: string
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(claimBytes)
  } catch {
    return 'invalid'
  }
  try {
    const parsed = JSON.parse(json)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return 'invalid'
    }
    return parsed as Record<string, unknown>
  } catch {
    return 'invalid'
  }
}

function tryDecodeFooter(footer: string): string | undefined {
  try {
    const bytes = base64UrlDecodeBytes(footer)
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    // Only return printable / JSON-looking footers — otherwise leave undefined.
    if (/^[\x09\x0a\x0d\x20-\x7e]*$/.test(text)) return text
    return undefined
  } catch {
    return undefined
  }
}
