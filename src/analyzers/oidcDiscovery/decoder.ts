/**
 * OIDC discovery (well-known/openid-configuration) decoder.
 *
 * Strict JSON shape check — we only treat input as an OIDC discovery
 * document if it parses to an object containing all three required
 * fields per OpenID Connect Discovery 1.0 §3:
 *   - `issuer`
 *   - `jwks_uri`
 *   - `authorization_endpoint`
 *
 * That trio is a very sharp signature — no realistic non-OIDC JSON
 * contains all three by accident — so we don't need a filename hint.
 */

export interface DecodedOidcConfig {
  issuer: string
  jwksUri: string
  authorizationEndpoint: string
  tokenEndpoint?: string
  userinfoEndpoint?: string
  idTokenSigningAlgValuesSupported?: string[]
  scopesSupported?: string[]
  responseTypesSupported?: string[]
  raw: Record<string, unknown>
}

/**
 * Decode an OIDC discovery document. Returns `undefined` if the text
 * is not JSON, not an object, or is missing any of the three required
 * fields. Never throws.
 */
export function decodeOidcDiscovery(text: string): DecodedOidcConfig | undefined {
  if (typeof text !== 'string') return undefined
  // Cheap leading-character gate — the spec mandates a JSON object,
  // so anything not starting with `{` (after whitespace) can't be one.
  const trimmedStart = leadingNonWhitespaceChar(text)
  if (trimmedStart !== '{') return undefined

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return undefined
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined
  const obj = parsed as Record<string, unknown>

  const issuer = stringOrUndef(obj.issuer)
  const jwksUri = stringOrUndef(obj.jwks_uri)
  const authorizationEndpoint = stringOrUndef(obj.authorization_endpoint)
  if (!issuer || !jwksUri || !authorizationEndpoint) return undefined

  return {
    issuer,
    jwksUri,
    authorizationEndpoint,
    tokenEndpoint: stringOrUndef(obj.token_endpoint),
    userinfoEndpoint: stringOrUndef(obj.userinfo_endpoint),
    idTokenSigningAlgValuesSupported: stringArrayOrUndef(obj.id_token_signing_alg_values_supported),
    scopesSupported: stringArrayOrUndef(obj.scopes_supported),
    responseTypesSupported: stringArrayOrUndef(obj.response_types_supported),
    raw: obj,
  }
}

function leadingNonWhitespaceChar(text: string): string | undefined {
  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i)
    if (ch !== ' ' && ch !== '\t' && ch !== '\n' && ch !== '\r') return ch
  }
  return undefined
}

function stringOrUndef(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

function stringArrayOrUndef(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined
  const arr = v.filter((x): x is string => typeof x === 'string')
  return arr.length ? arr : undefined
}
