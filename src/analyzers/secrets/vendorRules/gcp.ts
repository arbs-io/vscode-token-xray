import { SecretRule } from '../types'

const SERVICE_ACCOUNT_MARKER: SecretRule = {
  id: 'secret.gcp.serviceAccount',
  vendor: 'gcp',
  name: 'GCP service-account credentials file',
  pattern: /"type"\s*:\s*"service_account"/g,
  severity: 'error',
  description:
    'GCP service-account JSON detected. These files grant the SA\'s full permissions; treat them like a password and never commit to source.',
  docUrl: 'https://cloud.google.com/iam/docs/service-account-credentials',
}

const API_KEY: SecretRule = {
  id: 'secret.gcp.apiKey',
  vendor: 'gcp',
  name: 'Google API key',
  pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  severity: 'warning',
  description:
    'Google / Firebase / Maps API key. Restrict by referrer or IP in the Cloud Console — even restricted keys should not be committed.',
  docUrl: 'https://cloud.google.com/docs/authentication/api-keys',
}

const OAUTH_CLIENT_SECRET: SecretRule = {
  id: 'secret.gcp.oauthClientSecret',
  vendor: 'gcp',
  name: 'Google OAuth client secret',
  pattern: /"client_secret"\s*:\s*"[A-Za-z0-9_-]{20,}"/g,
  severity: 'error',
  description:
    'Google OAuth 2.0 client_secret. Confidential credential — required only by server-side OAuth flows.',
  sensitiveSpan: (raw) => {
    const m = /"([A-Za-z0-9_-]{20,})"$/.exec(raw)
    if (!m) return { start: 0, end: raw.length }
    const start = raw.lastIndexOf(m[1])
    return { start, end: start + m[1].length }
  },
}

const OAUTH_REFRESH_TOKEN: SecretRule = {
  id: 'secret.gcp.oauthRefreshToken',
  vendor: 'gcp',
  name: 'Google OAuth refresh token',
  pattern: /\b1\/\/[A-Za-z0-9_-]{40,}\b/g,
  severity: 'error',
  description:
    'Google OAuth refresh token. Grants long-lived re-authentication; treat as a password.',
}

const OAUTH_ACCESS_TOKEN: SecretRule = {
  id: 'secret.gcp.oauthAccessToken',
  vendor: 'gcp',
  name: 'Google OAuth access token',
  pattern: /\bya29\.[A-Za-z0-9_-]{20,}\b/g,
  severity: 'warning',
  description: 'Google OAuth access token (short-lived, typically expires in 1 hour).',
}

export const GCP_SECRET_RULES: SecretRule[] = [
  SERVICE_ACCOUNT_MARKER,
  API_KEY,
  OAUTH_CLIENT_SECRET,
  OAUTH_REFRESH_TOKEN,
  OAUTH_ACCESS_TOKEN,
]
