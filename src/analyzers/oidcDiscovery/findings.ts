import { Finding } from '../../core/types'
import { DecodedOidcConfig } from './decoder'

/**
 * Evaluate an OIDC discovery document and surface security findings.
 *
 * Findings:
 *   - `oidcDiscovery.algs.noneAllowed`     (error)   — `none` advertised in `id_token_signing_alg_values_supported`
 *   - `oidcDiscovery.algs.weakHs256Allowed` (info)   — HS256 (symmetric) advertised (unusual for OIDC)
 *   - `oidcDiscovery.endpoint.notHttps`    (warning) — issuer / jwks_uri / *_endpoint isn't HTTPS
 */
export function evaluateOidcDiscovery(config: DecodedOidcConfig): Finding[] {
  const out: Finding[] = []

  const algs = config.idTokenSigningAlgValuesSupported ?? []
  if (algs.some(eqIgnoreCase('none'))) {
    out.push({
      id: 'oidcDiscovery.algs.noneAllowed',
      severity: 'error',
      message:
        'Discovery document advertises "none" in id_token_signing_alg_values_supported — unsigned ID tokens would be accepted.',
    })
  }

  if (algs.some(eqIgnoreCase('HS256'))) {
    out.push({
      id: 'oidcDiscovery.algs.weakHs256Allowed',
      severity: 'info',
      message:
        'HS256 is a symmetric algorithm — clients must share a secret with the IdP. Most OIDC deployments prefer asymmetric (RS256 / ES256).',
    })
  }

  // Endpoint scheme check — every URL we know about should be HTTPS.
  // Build (label, url) pairs and report each non-HTTPS one once.
  const pairs: Array<[string, string | undefined]> = [
    ['issuer', config.issuer],
    ['jwks_uri', config.jwksUri],
    ['authorization_endpoint', config.authorizationEndpoint],
    ['token_endpoint', config.tokenEndpoint],
    ['userinfo_endpoint', config.userinfoEndpoint],
  ]
  for (const [label, url] of pairs) {
    if (!url) continue
    if (!isHttps(url)) {
      out.push({
        id: 'oidcDiscovery.endpoint.notHttps',
        severity: 'warning',
        message: `${label} is not HTTPS: "${url}". OIDC endpoints must use TLS in production.`,
      })
    }
  }

  return out
}

function eqIgnoreCase(target: string): (v: string) => boolean {
  const t = target.toLowerCase()
  return (v: string) => v.toLowerCase() === t
}

function isHttps(url: string): boolean {
  // We intentionally do not use the WHATWG URL parser — that would reject
  // relative or malformed entries silently. A simple prefix check matches
  // the user-visible signal: "does this URL start with https://".
  return /^https:\/\//i.test(url)
}
