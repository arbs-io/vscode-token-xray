import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// Atlassian Cloud API tokens carry the literal `ATATT3xFfGF0` prefix (the
// initial twelve characters uniquely identify the format) followed by a
// signed body. Real-world samples are ~192 chars in total — the body is
// ~180 base64url-ish characters then a fixed-length 8-char checksum suffix.
// The negative lookbehind/lookahead anchor the match against surrounding
// identifier context so we never extract a token out of a longer word
// such as `ATATT_OTHER…`. We use a fixed [A-Za-z0-9] tail so unrelated
// labels like `ATATT3xFfGF0_OTHER` (which contain `_`/`-` in the body)
// cannot accidentally satisfy the trailing checksum portion.
const ATLASSIAN_API_TOKEN: SecretRule = {
  id: 'secret.atlassian.apiToken',
  vendor: 'atlassian',
  name: 'Atlassian Cloud API token (ATATT3xFfGF0…)',
  pattern: /(?<!\w)ATATT3xFfGF0[A-Za-z0-9_=+-]{180,}[A-Za-z0-9]{8}(?!\w)/g,
  severity: 'error',
  description:
    'Atlassian Cloud API token (e.g. Jira / Confluence Cloud). Grants account-level API access — revoke immediately if leaked.',
  docUrl: 'https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/',
}

const JIRA_API_TOKEN_LABELLED: SecretRule = {
  id: 'secret.atlassian.jiraApiTokenLabelled',
  vendor: 'atlassian',
  name: 'Jira API token (env-labelled JIRA_API_TOKEN=)',
  pattern: /(?:JIRA_API_TOKEN|jira_api_token|jiraApiToken)["']?\s*[:=]\s*["']?[A-Za-z0-9._=+/-]{16,}["']?/g,
  severity: 'error',
  description:
    'Jira API token referenced via env var. Anyone with the value can call the Jira Cloud API as the issuing account — revoke immediately if leaked.',
  docUrl: 'https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._=+/-]{16,})/),
}

const CONFLUENCE_API_TOKEN_LABELLED: SecretRule = {
  id: 'secret.atlassian.confluenceApiTokenLabelled',
  vendor: 'atlassian',
  name: 'Confluence API token (env-labelled CONFLUENCE_API_TOKEN=)',
  pattern: /(?:CONFLUENCE_API_TOKEN|confluence_api_token|confluenceApiToken)["']?\s*[:=]\s*["']?[A-Za-z0-9._=+/-]{16,}["']?/g,
  severity: 'error',
  description:
    'Confluence API token referenced via env var. Anyone with the value can call the Confluence Cloud API as the issuing account — revoke immediately if leaked.',
  docUrl: 'https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._=+/-]{16,})/),
}

const OAUTH_CLIENT_SECRET_LABELLED: SecretRule = {
  id: 'secret.atlassian.oauthClientSecretLabelled',
  vendor: 'atlassian',
  name: 'Atlassian OAuth client_secret (env-labelled ATLASSIAN_OAUTH_CLIENT_SECRET=)',
  pattern: /(?:ATLASSIAN_OAUTH_CLIENT_SECRET|atlassian_oauth_client_secret|atlassianOauthClientSecret)["']?\s*[:=]\s*["']?[A-Za-z0-9._=+/-]{20,}["']?/g,
  severity: 'error',
  description:
    'Atlassian OAuth 2.0 (3LO) client_secret. Confidential server-side credential — rotate immediately if leaked.',
  docUrl: 'https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._=+/-]{20,})/),
}

export const ATLASSIAN_SECRET_RULES: SecretRule[] = [
  ATLASSIAN_API_TOKEN,
  JIRA_API_TOKEN_LABELLED,
  CONFLUENCE_API_TOKEN_LABELLED,
  OAUTH_CLIENT_SECRET_LABELLED,
]
