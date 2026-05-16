import { SecretRule } from '../types'

// Productivity / collaboration SaaS vendor token formats: Notion integration
// tokens, Linear API + OAuth tokens, Figma personal access tokens, Postman
// API keys, and labelled env-form Asana / Monday.com personal access tokens.
// Each pattern is anchored against the surrounding identifier charset with a
// negative lookbehind / lookahead so an identifier such as `xsecret_…` (a
// variable name) cannot accidentally extract a token out of a longer word.

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// Notion internal integration tokens carry the literal `secret_` prefix
// followed by exactly 43 alnum characters. The leading `secret_` is a
// generic English word, so we anchor the lookbehind/lookahead against the
// surrounding identifier charset (`[A-Za-z0-9_-]`) so identifiers such as
// `xsecret_abc…` or `my_secret_…` cannot extract a token. The trailing
// lookahead uses bare alnum so a 44th alnum character (which would make
// the token a different shape) breaks the match.
const NOTION_INTEGRATION_TOKEN: SecretRule = {
  id: 'secret.notion.integrationToken',
  vendor: 'notion',
  name: 'Notion integration token (secret_…)',
  pattern: /(?<![A-Za-z0-9_-])secret_[A-Za-z0-9]{43}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Notion internal integration token. Grants Notion API access scoped to the integration — revoke immediately via the Notion integrations dashboard if leaked.',
  docUrl: 'https://developers.notion.com/docs/authorization',
}

// Linear personal API keys carry the literal `lin_api_` prefix followed by
// exactly 40 alnum characters. The leading prefix is uniquely identifying;
// the negative lookbehind anchors against an identifier-context prefix
// (`[A-Za-z0-9_]`) so `xlin_api_…` is rejected. Body alphabet is bare
// alnum — Linear's docs show the key body never contains `_` or `-`.
const LINEAR_API_KEY: SecretRule = {
  id: 'secret.linear.apiKey',
  vendor: 'linear',
  name: 'Linear personal API key (lin_api_…)',
  pattern: /(?<![A-Za-z0-9_])lin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Linear personal API key. Authenticates against the Linear GraphQL API as the issuing user — revoke immediately via the Linear settings if leaked.',
  docUrl: 'https://developers.linear.app/docs/graphql/working-with-the-graphql-api#personal-api-keys',
}

// Linear OAuth access tokens carry the literal `lin_oauth_` prefix followed
// by 40 or more alnum characters. Linear's docs do not pin an upper bound on
// the body, so we accept `{40,}`. The lookahead requires the trailing char
// to be outside the alnum body so a 41st (or later) alnum char does not
// truncate the match.
const LINEAR_OAUTH_TOKEN: SecretRule = {
  id: 'secret.linear.oauthToken',
  vendor: 'linear',
  name: 'Linear OAuth access token (lin_oauth_…)',
  pattern: /(?<![A-Za-z0-9_])lin_oauth_[A-Za-z0-9]{40,}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Linear OAuth access token. Grants Linear GraphQL API access on behalf of the issuing user / workspace — revoke immediately if leaked.',
  docUrl: 'https://developers.linear.app/docs/oauth/authentication',
}

// Figma personal access tokens carry the literal `figd_` prefix followed by
// 40 or more base64url-ish characters (Figma's tokens include `_` and `-`).
// The lookbehind/lookahead anchors against the base64url surrounding charset
// so an identifier such as `xfigd_…` cannot extract a token.
const FIGMA_PAT: SecretRule = {
  id: 'secret.figma.pat',
  vendor: 'figma',
  name: 'Figma personal access token (figd_…)',
  pattern: /(?<![A-Za-z0-9_-])figd_[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Figma personal access token. Grants Figma REST API access as the issuing user (read files, comments, libraries) — revoke immediately via Figma account settings if leaked.',
  docUrl: 'https://www.figma.com/developers/api#access-tokens',
}

// Postman API keys carry the literal `PMAK-` prefix followed by exactly
// 24 lowercase hex chars, a `-` separator, and 34 lowercase hex chars. The
// lookbehind/lookahead anchors against bare alnum so identifier-context
// extraction is rejected (`xPMAK-…` and `PMAK-…x` both fail). Body chars
// are intentionally strict (lowercase hex only) — Postman's published
// format never includes uppercase letters or `_`/`-` outside the fixed
// dash separator.
const POSTMAN_API_KEY: SecretRule = {
  id: 'secret.postman.apiKey',
  vendor: 'postman',
  name: 'Postman API key (PMAK-…)',
  pattern: /(?<![A-Za-z0-9])PMAK-[a-f0-9]{24}-[a-f0-9]{34}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Postman API key. Grants Postman API access (workspaces, collections, environments) on behalf of the issuing user — revoke immediately via Postman account settings if leaked.',
  docUrl: 'https://learning.postman.com/docs/developer/postman-api/authentication/',
}

// Asana personal access tokens have no fixed prefix (they are 40+ char
// strings emitted by the Asana developer console), so we only surface
// the env-labelled form here. The body alphabet is base64url-ish — Asana
// PATs use lowercase letters, digits, and `/` separators in some
// generations, but the most conservative match is `[A-Za-z0-9._=+/-]{16,}`
// which is the same value charset every other labelled rule uses.
const ASANA_PAT_LABELLED: SecretRule = {
  id: 'secret.asana.patLabelled',
  vendor: 'asana',
  name: 'Asana personal access token (env-labelled ASANA_PAT=/ASANA_TOKEN=)',
  pattern: /(?:ASANA_PAT|ASANA_TOKEN|asana_pat|asana_token|asanaPat|asanaToken)["']?\s*[:=]\s*["']?[A-Za-z0-9._=+/-]{16,}["']?/g,
  severity: 'error',
  description:
    'Asana personal access token referenced via env var. Grants Asana API access as the issuing user — revoke immediately via Asana developer console if leaked.',
  docUrl: 'https://developers.asana.com/docs/personal-access-token',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._=+/-]{16,})/),
}

// Monday.com API tokens are JWT-shaped strings emitted by the Monday
// developer console; they share the standard JWT three-segment shape with
// other vendors, so we only surface the env-labelled form here. The value
// charset accommodates the JWT alphabet (`A-Za-z0-9._=+/-`).
const MONDAY_TOKEN_LABELLED: SecretRule = {
  id: 'secret.monday.tokenLabelled',
  vendor: 'monday',
  name: 'Monday.com API token (env-labelled MONDAY_API_TOKEN=)',
  pattern: /(?:MONDAY_API_TOKEN|MONDAY_TOKEN|monday_api_token|monday_token|mondayApiToken|mondayToken)["']?\s*[:=]\s*["']?[A-Za-z0-9._=+/-]{16,}["']?/g,
  severity: 'error',
  description:
    'Monday.com API token referenced via env var. Grants Monday.com GraphQL API access as the issuing user — revoke immediately via Monday developer console if leaked.',
  docUrl: 'https://developer.monday.com/api-reference/docs/authentication',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._=+/-]{16,})/),
}

export const PRODUCTIVITY_SECRET_RULES: SecretRule[] = [
  NOTION_INTEGRATION_TOKEN,
  LINEAR_API_KEY,
  LINEAR_OAUTH_TOKEN,
  FIGMA_PAT,
  POSTMAN_API_KEY,
  ASANA_PAT_LABELLED,
  MONDAY_TOKEN_LABELLED,
]
