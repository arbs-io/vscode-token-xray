import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// Matches the common labels SailPoint customers and integrations use.
const ID_LABEL = '(?:SAIL_CLIENT_ID|SAILPOINT_CLIENT_ID|IDN_CLIENT_ID|ISC_CLIENT_ID|sail_client_id|sailpoint_client_id|idn_client_id|isc_client_id|sailClientId|sailpointClientId|idnClientId|iscClientId)'
const SECRET_LABEL = '(?:SAIL_CLIENT_SECRET|SAILPOINT_CLIENT_SECRET|IDN_CLIENT_SECRET|ISC_CLIENT_SECRET|sail_client_secret|sailpoint_client_secret|idn_client_secret|isc_client_secret|sailClientSecret|sailpointClientSecret|idnClientSecret|iscClientSecret)'
const TENANT_LABEL = '(?:SAIL_TENANT|SAIL_BASE_URL|SAILPOINT_TENANT|IDN_TENANT|ISC_TENANT|sail_tenant|sail_base_url|sailpoint_tenant|idn_tenant|isc_tenant)'

const CLIENT_ID: SecretRule = {
  id: 'secret.sailpoint.clientId',
  vendor: 'sailpoint',
  name: 'SailPoint API client_id (labelled)',
  pattern: new RegExp(
    `${ID_LABEL}["']?\\s*[:=]\\s*["']?[0-9a-fA-F]{32}["']?`,
    'g'
  ),
  severity: 'info',
  description: 'SailPoint Identity Security Cloud API client_id. Identifier only; not secret on its own.',
  docUrl: 'https://developer.sailpoint.com/docs/api/authentication',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([0-9a-fA-F]{32})/),
}

const CLIENT_SECRET: SecretRule = {
  id: 'secret.sailpoint.clientSecret',
  vendor: 'sailpoint',
  name: 'SailPoint API client_secret (labelled)',
  pattern: new RegExp(
    `${SECRET_LABEL}["']?\\s*[:=]\\s*["']?[A-Za-z0-9_-]{40,}["']?`,
    'g'
  ),
  severity: 'error',
  description: 'SailPoint Identity Security Cloud API client_secret. Grants API access scoped to the client. Rotate immediately if leaked.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{40,})/),
}

const TENANT_URL: SecretRule = {
  id: 'secret.sailpoint.tenantUrl',
  vendor: 'sailpoint',
  name: 'SailPoint tenant URL (labelled)',
  pattern: new RegExp(
    `${TENANT_LABEL}["']?\\s*[:=]\\s*["']?(?:https?:\\/\\/)?[a-z0-9-]+\\.api\\.identitynow\\.com[A-Za-z0-9/_.-]*["']?`,
    'g'
  ),
  severity: 'info',
  description: 'SailPoint tenant identifier in an env variable. Not a secret on its own but identifies the tenant for an attacker.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?((?:https?:\/\/)?[a-z0-9-]+\.api\.identitynow\.com[A-Za-z0-9/_.-]*)/),
}

export const SAILPOINT_SECRET_RULES: SecretRule[] = [
  CLIENT_ID,
  CLIENT_SECRET,
  TENANT_URL,
]
