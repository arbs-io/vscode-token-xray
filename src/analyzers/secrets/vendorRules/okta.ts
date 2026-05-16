import { SecretRule } from '../types'

const SSWS_HEADER: SecretRule = {
  id: 'secret.okta.sswsHeader',
  vendor: 'okta',
  name: 'Okta API token (SSWS scheme)',
  pattern: /SSWS\s+[A-Za-z0-9_-]{30,}/g,
  severity: 'error',
  description:
    'Okta admin API token (SSWS scheme). Grants tenant-wide admin access — rotate immediately if leaked.',
  docUrl: 'https://developer.okta.com/docs/guides/create-an-api-token/main/',
  sensitiveSpan: (raw) => {
    const m = /SSWS\s+([A-Za-z0-9_-]{30,})/.exec(raw)
    if (!m) return { start: 0, end: raw.length }
    const start = raw.indexOf(m[1])
    return { start, end: start + m[1].length }
  },
}

const API_TOKEN_LABEL: SecretRule = {
  id: 'secret.okta.apiToken',
  vendor: 'okta',
  name: 'Okta API token (labelled)',
  pattern: /(?:OKTA_API_TOKEN|okta_api_token|oktaApiToken)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{30,}["']?/g,
  severity: 'error',
  description: 'Okta API token assigned to a labelled variable. Grants admin API access.',
  sensitiveSpan: (raw) => {
    const m = /[:=]\s*["']?([A-Za-z0-9_-]{30,})/.exec(raw)
    if (!m) return { start: 0, end: raw.length }
    const start = raw.lastIndexOf(m[1])
    return { start, end: start + m[1].length }
  },
}

const CLIENT_SECRET_LABEL: SecretRule = {
  id: 'secret.okta.clientSecret',
  vendor: 'okta',
  name: 'Okta OAuth client secret (labelled)',
  pattern: /(?:OKTA_CLIENT_SECRET|okta_client_secret|oktaClientSecret)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?/g,
  severity: 'error',
  description:
    'Okta OAuth 2.0 client secret. Confidential credential for the server-side authorization code or client credentials grant.',
  sensitiveSpan: (raw) => {
    const m = /[:=]\s*["']?([A-Za-z0-9_-]{20,})/.exec(raw)
    if (!m) return { start: 0, end: raw.length }
    const start = raw.lastIndexOf(m[1])
    return { start, end: start + m[1].length }
  },
}

export const OKTA_SECRET_RULES: SecretRule[] = [
  SSWS_HEADER,
  API_TOKEN_LABEL,
  CLIENT_SECRET_LABEL,
]
