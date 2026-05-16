/**
 * Decoded HTTP Basic credential — the result of base64-decoding the
 * `<base64>` portion of `Authorization: Basic <base64>` and splitting on
 * the first colon.
 */
export interface DecodedBasic {
  /** The username portion (everything before the first `:`). */
  user: string
  /** The password portion (everything after the first `:`). May contain colons. */
  password: string
}

/**
 * Base64-decode a HTTP Basic credential payload and split on the first colon.
 *
 * Returns `undefined` when:
 *   - the input is empty / non-string
 *   - the input is not valid base64
 *   - the decoded bytes are not valid UTF-8
 *   - the decoded string contains no colon (no `user:pass` shape)
 *   - the username or password portion is empty (`:pass` or `user:` is invalid)
 *
 * Trailing whitespace, CR and LF are tolerated on the input. The decoded
 * username is also trimmed (e.g. of an accidental trailing newline that
 * sometimes appears when the base64 was sliced out of a wider buffer).
 * The password is returned as-is — only the leading/trailing CR/LF that
 * came from the encoded blob itself are stripped, so passwords containing
 * spaces remain intact.
 */
export function decodeBasic(token: string): DecodedBasic | undefined {
  if (typeof token !== 'string') return undefined
  const trimmed = token.replace(/[\s]+$/u, '')
  if (trimmed.length === 0) return undefined

  // Reject anything containing characters outside the base64 alphabet
  // (including the standard `+/=` plus the URL-safe variants).
  if (!/^[A-Za-z0-9+/_=-]+$/.test(trimmed)) return undefined

  // Normalise URL-safe → standard base64. RFC 7617 only specifies the
  // standard alphabet but real-world headers occasionally use the URL-safe
  // form; we tolerate it.
  let normalised = trimmed.replace(/-/g, '+').replace(/_/g, '/')

  // Pad to a multiple of 4 so atob doesn't reject otherwise-valid input.
  const mod = normalised.length % 4
  if (mod === 1) return undefined
  if (mod === 2) normalised += '=='
  else if (mod === 3) normalised += '='

  let decoded: string
  try {
    const binary = atob(normalised)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return undefined
  }

  // Strip any trailing CR/LF that crept in via the encoded blob.
  const cleaned = decoded.replace(/[\r\n]+$/u, '')

  const colon = cleaned.indexOf(':')
  if (colon < 0) return undefined

  const user = cleaned.slice(0, colon)
  const password = cleaned.slice(colon + 1)
  if (user.length === 0 || password.length === 0) return undefined

  return { user, password }
}
