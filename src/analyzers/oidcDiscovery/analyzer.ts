import { Analyzer, AnalysisResult, Finding, Match, Section, SectionRow } from '../../core/types'
import { DecodedOidcConfig, decodeOidcDiscovery } from './decoder'
import { evaluateOidcDiscovery } from './findings'

/**
 * OIDC discovery analyzer — detects OpenID Connect Discovery 1.0
 * `well-known/openid-configuration` JSON documents.
 *
 * Detection signature: the document parses as a JSON object containing
 * all three required fields (`issuer`, `jwks_uri`, `authorization_endpoint`).
 * That trio is sharp enough to use as the sole heuristic — no realistic
 * non-OIDC JSON contains all three by accident.
 *
 * We don't have a filename in `detect()`, so the path-based heuristic
 * mentioned in the spec (".well-known/openid-configuration") isn't used.
 * The JSON-shape check covers the same ground.
 */
export class OidcDiscoveryAnalyzer implements Analyzer {
  readonly id = 'oidcDiscovery'
  readonly name = 'OIDC discovery document'

  detect(text: string): Match[] {
    if (!text) return []
    // Cheap leading-char gate — defer full JSON parse to decodeOidcDiscovery.
    if (!startsWithJsonObject(text)) return []
    const decoded = decodeOidcDiscovery(text)
    if (!decoded) return []
    return [{ text, range: { start: 0, end: text.length } }]
  }

  analyze(match: Match): AnalysisResult {
    const decoded = decodeOidcDiscovery(match.text)
    if (!decoded) {
      throw new Error('Input is not an OIDC discovery document.')
    }
    return buildResult(this.id, decoded)
  }
}

function startsWithJsonObject(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i)
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') continue
    return ch === '{'
  }
  return false
}

function buildResult(analyzerId: string, decoded: DecodedOidcConfig): AnalysisResult {
  const overview: SectionRow[] = [
    { key: 'issuer', value: decoded.issuer, description: 'Identifier of the OIDC provider.' },
    { key: 'jwks_uri', value: decoded.jwksUri, description: 'URL of the provider’s JWK Set document.' },
    {
      key: 'authorization_endpoint',
      value: decoded.authorizationEndpoint,
      description: 'OAuth 2.0 authorization endpoint.',
    },
  ]
  if (decoded.tokenEndpoint) {
    overview.push({
      key: 'token_endpoint',
      value: decoded.tokenEndpoint,
      description: 'OAuth 2.0 token endpoint.',
    })
  }
  if (decoded.userinfoEndpoint) {
    overview.push({
      key: 'userinfo_endpoint',
      value: decoded.userinfoEndpoint,
      description: 'OIDC UserInfo endpoint.',
    })
  }

  const capabilities: SectionRow[] = []
  if (decoded.idTokenSigningAlgValuesSupported?.length) {
    capabilities.push({
      key: 'id_token_signing_alg_values_supported',
      value: decoded.idTokenSigningAlgValuesSupported.join(', '),
      description: 'Signing algorithms the provider may use for ID tokens.',
    })
  }
  if (decoded.scopesSupported?.length) {
    capabilities.push({
      key: 'scopes_supported',
      value: decoded.scopesSupported.join(', '),
      description: 'Scope values the provider advertises.',
    })
  }
  if (decoded.responseTypesSupported?.length) {
    capabilities.push({
      key: 'response_types_supported',
      value: decoded.responseTypesSupported.join(', '),
      description: 'OAuth 2.0 response_type values the provider supports.',
    })
  }

  const sections: Section[] = [{ id: 'overview', title: 'Endpoints', rows: overview }]
  if (capabilities.length) {
    sections.push({ id: 'capabilities', title: 'Capabilities', rows: capabilities })
  }

  const findings: Finding[] = evaluateOidcDiscovery(decoded)

  return {
    analyzerId,
    kind: 'OIDC discovery document',
    sections,
    findings,
    raw: decoded,
  }
}
