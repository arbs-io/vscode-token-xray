/**
 * Parsed structural components of an `Authorization: AWS4-HMAC-SHA256` header.
 *
 * Example header value:
 *   `AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024`
 *
 * The credential scope is `<access-key-id>/<date>/<region>/<service>/aws4_request`.
 * SignedHeaders is a `;`-delimited list (case-insensitive but typically lower-cased).
 * Signature is the lowercase hex digest of the StringToSign.
 */
export interface Sigv4Components {
  /** AWS access key id — `AKIA…` (long-term) or `ASIA…` (STS session). */
  accessKeyId: string
  /** YYYYMMDD date pulled from the credential scope (request date). */
  date: string
  /** AWS region pulled from the credential scope (e.g. `us-east-1`). */
  region: string
  /** AWS service pulled from the credential scope (e.g. `s3`, `iam`). */
  service: string
  /** `;`-delimited list of canonical signed headers, lower-cased. */
  signedHeaders: string[]
  /** Lowercase hex signature digest. */
  signature: string
}

/**
 * Pure regex parser for a single AWS SigV4 Authorization header value.
 *
 * Accepts either the full header (`Authorization: AWS4-HMAC-SHA256 …`) or the
 * bare value (`AWS4-HMAC-SHA256 …`). Whitespace around commas and between
 * `<key>=` and the value is tolerated since real-world clients format these
 * inconsistently.
 *
 * Returns `undefined` when any required field is missing or malformed:
 *   - missing `AWS4-HMAC-SHA256` algorithm
 *   - missing `Credential=` / `SignedHeaders=` / `Signature=`
 *   - credential scope does not have exactly 5 `/`-delimited parts ending in
 *     `aws4_request`
 *   - access key id does not match the `AKIA…` / `ASIA…` shape (16-20 chars
 *     of uppercase / digits after the prefix)
 *   - date is not exactly 8 digits (YYYYMMDD)
 *   - signature is not a non-empty lowercase hex string
 *   - signedHeaders is empty after splitting
 */
export function parseSigv4Authorization(header: string): Sigv4Components | undefined {
  if (typeof header !== 'string') return undefined
  const trimmed = header.replace(/^\s*Authorization\s*[:=]\s*/i, '').trim()
  if (trimmed.length === 0) return undefined

  // Algorithm token must lead the value.
  if (!/^AWS4-HMAC-SHA256\b/i.test(trimmed)) return undefined

  const credentialMatch = /Credential\s*=\s*([^,\s]+)/i.exec(trimmed)
  const signedHeadersMatch = /SignedHeaders\s*=\s*([^,\s]+)/i.exec(trimmed)
  const signatureMatch = /Signature\s*=\s*([A-Fa-f0-9]+)/i.exec(trimmed)
  if (!credentialMatch || !signedHeadersMatch || !signatureMatch) return undefined

  const credentialParts = credentialMatch[1].split('/')
  if (credentialParts.length !== 5) return undefined
  const [accessKeyId, date, region, service, terminator] = credentialParts
  if (terminator !== 'aws4_request') return undefined

  if (!/^(?:AKIA|ASIA)[A-Z0-9]{12,16}$/.test(accessKeyId)) return undefined
  if (!/^\d{8}$/.test(date)) return undefined
  if (region.length === 0 || service.length === 0) return undefined

  const signedHeaders = signedHeadersMatch[1]
    .split(';')
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0)
  if (signedHeaders.length === 0) return undefined

  const signature = signatureMatch[1].toLowerCase()

  return {
    accessKeyId,
    date,
    region,
    service,
    signedHeaders,
    signature,
  }
}
