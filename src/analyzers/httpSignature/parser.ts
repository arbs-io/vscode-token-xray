/**
 * Parsed structural components of an HTTP signature header.
 *
 * Two related formats are supported:
 *
 *   1. Draft Cavage (draft-cavage-http-signatures, IETF http-signatures
 *      working group). Used in production today. Single `Signature:`
 *      header with a comma-separated list of `key="value"` pairs:
 *
 *        Signature: keyId="alice",algorithm="rsa-sha256",
 *                   headers="(request-target) host date",
 *                   signature="base64=="
 *
 *      Required: `keyId`, `signature`. Optional: `algorithm`, `headers`,
 *      `created`, `expires`.
 *
 *   2. RFC 9421 (current standard, "Message Signatures"). Two headers:
 *
 *        Signature-Input: sig1=("@method" "@path" "host");
 *                         created=1402170695;keyid="test-key-b"
 *        Signature: sig1=:base64==:
 *
 *      `Signature-Input` describes the covered components and metadata.
 *      `Signature` carries the byte-string in `sig1=:<base64>:` form.
 *      Algorithm is intentionally absent from the wire format — it is
 *      derived from the key reference.
 */

export interface CavageSig {
  /** Required: opaque identifier for the key used to sign. */
  keyId: string
  /** Optional: signature algorithm (e.g. `rsa-sha256`, `hmac-sha256`). */
  algorithm?: string
  /** Optional: ordered list of headers covered by the signature. */
  headers?: string[]
  /** Optional: signature creation time (Unix seconds). */
  created?: number
  /** Optional: signature expiry time (Unix seconds). */
  expires?: number
  /** Required: base64 signature blob. */
  signature: string
}

export interface Rfc9421Sig {
  /** Label assigned to this signature (e.g. `sig1`). */
  label: string
  /**
   * Ordered list of covered components — derived identifiers like
   * `@method`, `@path`, plus regular HTTP header names like `host`.
   */
  components: string[]
  /** Optional: signature creation time (Unix seconds). */
  created?: number
  /** Optional: signature expiry time (Unix seconds). */
  expires?: number
  /** Optional: key reference (`keyid` parameter on Signature-Input). */
  keyId?: string
  /** Optional: nonce parameter on Signature-Input. */
  nonce?: string
  /** Optional: algorithm parameter (RFC 9421 allows this but discourages it). */
  algorithm?: string
  /** Optional: base64 signature blob extracted from the Signature header. */
  signature?: string
}

/**
 * Split a Cavage signature header on commas that are NOT inside double
 * quotes. Returns the raw `key="value"` chunks; further parsing happens
 * in `parseCavageSignature`.
 */
function splitOutsideQuotes(value: string): string[] {
  const parts: string[] = []
  let buf = ''
  let inQuotes = false
  for (let i = 0; i < value.length; i++) {
    const c = value.charAt(i)
    if (c === '"') {
      inQuotes = !inQuotes
      buf += c
      continue
    }
    if (c === ',' && !inQuotes) {
      parts.push(buf)
      buf = ''
      continue
    }
    buf += c
  }
  if (buf.length > 0) parts.push(buf)
  return parts
}

function stripPrefix(header: string): string {
  return header.replace(/^\s*Signature\s*[:=]\s*/i, '').trim()
}

function stripInputPrefix(header: string): string {
  return header.replace(/^\s*Signature-Input\s*[:=]\s*/i, '').trim()
}

/**
 * Parse a Cavage `Signature:` header value.
 *
 * Accepts the bare value (`keyId="…",signature="…"`) or the full header
 * line (`Signature: keyId="…",signature="…"`). Returns `undefined` when
 * required fields are missing or the structure is malformed.
 *
 * To disambiguate from the RFC 9421 form (which uses `<label>=:<b64>:`
 * for the signature), this parser requires at least one quoted
 * `key="value"` pair (the unquoted form would not appear in Cavage).
 */
function parseFields(parts: string[]): Record<string, string> | undefined {
  const fields: Record<string, string> = {}
  for (const part of parts) {
    const trimmedPart = part.trim()
    if (trimmedPart.length === 0) continue
    const m = /^([A-Za-z][A-Za-z0-9_-]*)\s*=\s*("([^"]*)"|(\d+))\s*$/.exec(trimmedPart)
    if (!m) return undefined
    const key = m[1].toLowerCase()
    // Quoted value is in group 3; bare numeric value is in group 4.
    fields[key] = m[3] ?? m[4]
  }
  return fields
}

function extractHeadersList(headers: string): string[] {
  return headers
    .split(/\s+/)
    .map((h) => h.trim())
    .filter((h) => h.length > 0)
}

export function parseCavageSignature(header: string): CavageSig | undefined {
  if (typeof header !== 'string') return undefined
  const trimmed = stripPrefix(header)
  if (trimmed.length === 0) return undefined

  // Reject the RFC 9421 shape outright: `<label>=("…" "…");…` or
  // `<label>=:base64==:`.
  if (/^[A-Za-z0-9_-]+\s*=\s*[(:]/.test(trimmed)) return undefined

  const parts = splitOutsideQuotes(trimmed)
  if (parts.length === 0) return undefined

  const fields = parseFields(parts)
  if (!fields) return undefined

  const keyId = fields.keyid
  const signature = fields.signature
  if (!keyId || !signature) return undefined

  const result: CavageSig = { keyId, signature }
  if (fields.algorithm) result.algorithm = fields.algorithm
  if (fields.headers) {
    const list = extractHeadersList(fields.headers)
    if (list.length > 0) result.headers = list
  }
  if (fields.created !== undefined && /^\d+$/.test(fields.created)) {
    result.created = Number(fields.created)
  }
  if (fields.expires !== undefined && /^\d+$/.test(fields.expires)) {
    result.expires = Number(fields.expires)
  }
  return result
}

/**
 * Split an RFC 9421 `Signature-Input` parameter list on semicolons that
 * are outside parentheses and outside double quotes. The covered-
 * components list is parenthesised so we treat it atomically.
 */
function splitParams(value: string): string[] {
  const parts: string[] = []
  let buf = ''
  let depth = 0
  let inQuotes = false
  for (let i = 0; i < value.length; i++) {
    const c = value.charAt(i)
    if (c === '"') {
      inQuotes = !inQuotes
      buf += c
      continue
    }
    if (!inQuotes) {
      if (c === '(') depth++
      else if (c === ')') depth = Math.max(0, depth - 1)
      else if (c === ';' && depth === 0) {
        parts.push(buf)
        buf = ''
        continue
      }
    }
    buf += c
  }
  if (buf.length > 0) parts.push(buf)
  return parts
}

/**
 * Parse an RFC 9421 `Signature-Input` (and optional matching
 * `Signature`) header pair.
 *
 *   Signature-Input: sig1=("@method" "@path");created=1402170695;
 *                    keyid="test-key-b"
 *   Signature: sig1=:base64==:
 *
 * Returns `undefined` when the Signature-Input header cannot be parsed.
 * The `Signature` header is optional — when supplied, the matching
 * label's base64 blob is extracted; mismatched labels are ignored.
 */
function applyRfc9421Param(result: Rfc9421Sig, key: string, value: string): void {
  switch (key) {
    case 'keyid':
      result.keyId = value
      return
    case 'nonce':
      result.nonce = value
      return
    case 'alg':
    case 'algorithm':
      result.algorithm = value
      return
    case 'created':
      if (/^\d+$/.test(value)) result.created = Number(value)
      return
    case 'expires':
      if (/^\d+$/.test(value)) result.expires = Number(value)
      return
  }
}

function applyRfc9421Params(result: Rfc9421Sig, paramsRaw: string): void {
  if (paramsRaw.trim().length === 0) return
  for (const part of splitParams(paramsRaw)) {
    const trimmedPart = part.trim()
    if (trimmedPart.length === 0) continue
    const m = /^([A-Za-z][A-Za-z0-9_-]*)\s*=\s*("([^"]*)"|(\d+))\s*$/.exec(trimmedPart)
    if (!m) continue
    applyRfc9421Param(result, m[1].toLowerCase(), m[3] ?? m[4])
  }
}

function findSignatureBlob(signatureHeader: string, label: string): string | undefined {
  const sigTrimmed = stripPrefix(signatureHeader)
  // Format: `<label>=:base64==:[, <label2>=:…:]`.
  const sigRegex = /([A-Za-z0-9_-]+)\s*=\s*:([^:]*):/g
  let m: RegExpExecArray | null
  while ((m = sigRegex.exec(sigTrimmed)) !== null) {
    if (m[1] === label) return m[2].length > 0 ? m[2] : undefined
  }
  return undefined
}

export function parseRfc9421(
  input: string,
  signatureHeader?: string
): Rfc9421Sig | undefined {
  if (typeof input !== 'string') return undefined
  const trimmed = stripInputPrefix(input)
  if (trimmed.length === 0) return undefined

  // Expected shape: `<label>=( "@method" "@path" );param=value;…`
  // The label is the first token before `=`. After the closing `)` of
  // the inner list the remaining text is a `;`-delimited parameter
  // bag.
  const labelMatch = /^([A-Za-z0-9_-]+)\s*=\s*\(([^)]*)\)\s*(?:;(.*))?$/.exec(trimmed)
  if (!labelMatch) return undefined
  const label = labelMatch[1]
  const componentsRaw = labelMatch[2]
  const paramsRaw = labelMatch[3] ?? ''

  // Covered components: whitespace-separated tokens, each optionally
  // quoted with `"…"`. Strip surrounding quotes; keep order.
  const components = componentsRaw
    .split(/\s+/)
    .map((c) => c.trim().replace(/^"(.*)"$/, '$1'))
    .filter((c) => c.length > 0)
  if (components.length === 0) return undefined

  const result: Rfc9421Sig = { label, components }
  applyRfc9421Params(result, paramsRaw)

  if (signatureHeader) {
    const sig = findSignatureBlob(signatureHeader, label)
    if (sig) result.signature = sig
  }
  return result
}
