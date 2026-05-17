import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

const CLIENT_SECRET: SecretRule = {
  id: 'secret.auth0.clientSecret',
  vendor: 'auth0',
  name: 'Auth0 OAuth client secret',
  pattern: /(?:AUTH0_CLIENT_SECRET|auth0_client_secret|auth0ClientSecret)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{32,}["']?/g,
  severity: 'error',
  description: 'Auth0 OAuth 2.0 client secret. Confidential — required only by server-side / M2M applications.',
  docUrl: 'https://auth0.com/docs/secure/application-credentials',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{32,})/),
}

const MANAGEMENT_API_TOKEN: SecretRule = {
  id: 'secret.auth0.managementApiToken',
  vendor: 'auth0',
  name: 'Auth0 Management API token',
  pattern: /(?:AUTH0_(?:API_|MGMT_|MANAGEMENT_)TOKEN|auth0(?:Api|Mgmt|Management)Token)["']?\s*[:=]\s*["']?eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+["']?/g,
  severity: 'error',
  description: 'Auth0 Management API token (JWT). Grants tenant-level admin access scoped to the granted `scope` claim.',
  docUrl: 'https://auth0.com/docs/api/management/v2',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?(eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+)/),
}

const TENANT_DOMAIN: SecretRule = {
  id: 'secret.auth0.tenantDomain',
  vendor: 'auth0',
  name: 'Auth0 tenant domain (env-labelled)',
  pattern: /(?:AUTH0_DOMAIN|auth0_domain|auth0Domain)["']?\s*[:=]\s*["']?[a-z0-9-]+(?:\.[a-z]{2,3})?\.auth0\.com["']?/g,
  severity: 'info',
  description: 'Auth0 tenant identifier in an env variable. Not a secret on its own but identifies the tenant for an attacker.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-z0-9-]+(?:\.[a-z]{2,3})?\.auth0\.com)/),
}

export const AUTH0_SECRET_RULES: SecretRule[] = [
  CLIENT_SECRET,
  MANAGEMENT_API_TOKEN,
  TENANT_DOMAIN,
]
