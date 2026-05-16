import { SecretRule } from '../types'

// Miscellaneous vendor token formats that don't cluster naturally with any
// other vendor rule file: Mapbox access tokens (`pk.…` / `sk.…`), Algolia
// admin keys (labelled), DigitalOcean personal access tokens (`dop_v1_…`),
// labelled Snyk + Heroku UUID tokens. Each non-labelled pattern is anchored
// against the surrounding identifier charset with negative lookbehind /
// lookahead so a token cannot be accidentally extracted from a longer
// identifier. The labelled UUID forms are only surfaced via their env-style
// label because a bare UUID is indistinguishable from countless other
// identifiers.

// Helper: find the value half of a labelled `KEY=<value>` / `KEY: <value>`
// pattern and return its absolute span within the matched raw string.
const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// Mapbox access tokens are JWT-shaped: a public-key prefix (`pk.` or `sk.`)
// + a 60+ base64url body + a `.` separator + a 20+ base64url signature.
// Mapbox's published tokens use base64url chars in both halves. The
// negative lookbehind/lookahead anchors against the base64url surrounding
// charset so an identifier such as `xpk.…` cannot extract a token.
//
// `pk.` tokens are designed to be exposed in client-side maps; we surface
// them at INFO severity so users are aware they're embedded (rotation is
// still a good idea if the token is over-scoped). `sk.` tokens (secret
// form) are server-side only and are flagged as error.
const MAPBOX_ACCESS_TOKEN: SecretRule = {
  id: 'secret.mapbox.accessToken',
  vendor: 'mapbox',
  name: 'Mapbox public access token (pk.…)',
  pattern: /(?<![A-Za-z0-9_-])pk\.[A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'info',
  description:
    'Mapbox public access token (pk.…). Public tokens are client-side by design (embedded in web/mobile map renders), but if leaked they may still grant more scope than intended — review the URL restrictions and scopes attached to the token.',
  docUrl: 'https://docs.mapbox.com/help/getting-started/access-tokens/',
}

// Mapbox secret-form access token. Same JWT-shaped envelope as the public
// form but begins with `sk.` instead of `pk.`. Secret tokens grant server-
// side scopes (uploads, dataset writes) and must never be committed.
const MAPBOX_SECRET_TOKEN: SecretRule = {
  id: 'secret.mapbox.secretToken',
  vendor: 'mapbox',
  name: 'Mapbox secret access token (sk.…)',
  pattern: /(?<![A-Za-z0-9_-])sk\.[A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Mapbox secret access token (sk.…). Grants server-side scopes (uploads, dataset writes, token management) against the issuing account — revoke immediately via the Mapbox account page if leaked.',
  docUrl: 'https://docs.mapbox.com/help/getting-started/access-tokens/',
}

// Algolia admin API keys are exactly 32 lowercase-hex characters and look
// identical to many other 32-hex hashes — we only surface them in their
// labelled env form. Both `ALGOLIA_ADMIN_KEY=` and `ALGOLIA_ADMIN_API_KEY=`
// are accepted, plus the camelCase equivalents commonly used in JS/TS
// configs.
const ALGOLIA_ADMIN_KEY_LABELLED: SecretRule = {
  id: 'secret.algolia.adminKeyLabelled',
  vendor: 'algolia',
  name: 'Algolia admin API key (env-labelled ALGOLIA_ADMIN_KEY=)',
  pattern: /(?:ALGOLIA_ADMIN_KEY|ALGOLIA_ADMIN_API_KEY|algolia_admin_key|algolia_admin_api_key|algoliaAdminKey|algoliaAdminApiKey)["']?\s*[:=]\s*["']?[a-f0-9]{32}["']?/g,
  severity: 'error',
  description:
    'Algolia admin API key referenced via env var. Grants full admin access to the Algolia application (index create/delete, settings, ACL management) — revoke immediately via the Algolia dashboard if leaked.',
  docUrl: 'https://www.algolia.com/doc/guides/security/api-keys/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-f0-9]{32})/),
}

// DigitalOcean personal access tokens carry the literal `dop_v1_` prefix
// followed by exactly 64 lowercase hex chars. The negative lookbehind /
// lookahead anchors against bare alnum + underscore so identifier-context
// extraction is rejected (`xdop_v1_…` and `dop_v1_…x` both fail).
const DIGITALOCEAN_PAT: SecretRule = {
  id: 'secret.digitalocean.personalAccessToken',
  vendor: 'digitalocean',
  name: 'DigitalOcean personal access token (dop_v1_…)',
  pattern: /(?<![A-Za-z0-9_])dop_v1_[a-f0-9]{64}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'DigitalOcean personal access token. Grants full DigitalOcean API access (droplets, networking, billing) on behalf of the issuing user — revoke immediately via the DigitalOcean control panel if leaked.',
  docUrl: 'https://docs.digitalocean.com/reference/api/create-personal-access-token/',
}

// Snyk tokens are UUID-shaped (8-4-4-4-12 lowercase hex with hyphens, 36
// chars total) and we only flag the env-labelled `SNYK_TOKEN=<uuid>` form
// because a bare UUID is indistinguishable from countless other identifiers.
const SNYK_TOKEN_LABELLED: SecretRule = {
  id: 'secret.snyk.tokenLabelled',
  vendor: 'snyk',
  name: 'Snyk API token (env-labelled SNYK_TOKEN=)',
  pattern: /(?:SNYK_TOKEN|SNYK_API_TOKEN|snyk_token|snyk_api_token|snykToken|snykApiToken)["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?/g,
  severity: 'error',
  description:
    'Snyk API token (UUID) referenced via env var. Grants Snyk API access (project tests, monitor, settings) on behalf of the issuing user / service account — revoke immediately via the Snyk dashboard if leaked.',
  docUrl: 'https://docs.snyk.io/snyk-api/authentication-for-api',
  sensitiveSpan: (raw) =>
    sensitiveAfterDelimiter(
      raw,
      /[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/
    ),
}

// Heroku API keys are UUID-shaped (8-4-4-4-12 lowercase hex with hyphens,
// 36 chars total) and like Snyk we only flag the labelled `HEROKU_API_KEY=`
// form. Both `HEROKU_API_KEY` and `HEROKU_AUTH_TOKEN` are accepted (the
// latter is what the Heroku CLI emits into `~/.netrc`).
const HEROKU_API_KEY_LABELLED: SecretRule = {
  id: 'secret.heroku.apiKeyLabelled',
  vendor: 'heroku',
  name: 'Heroku API key (env-labelled HEROKU_API_KEY=)',
  pattern: /(?:HEROKU_API_KEY|HEROKU_AUTH_TOKEN|heroku_api_key|heroku_auth_token|herokuApiKey|herokuAuthToken)["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?/g,
  severity: 'error',
  description:
    'Heroku API key (UUID) referenced via env var. Grants full Heroku Platform API access (apps, dynos, config vars, billing) on behalf of the issuing user — revoke immediately via `heroku authorizations:revoke` if leaked.',
  docUrl: 'https://devcenter.heroku.com/articles/platform-api-quickstart#authentication',
  sensitiveSpan: (raw) =>
    sensitiveAfterDelimiter(
      raw,
      /[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/
    ),
}

export const MISC_SECRET_RULES: SecretRule[] = [
  MAPBOX_ACCESS_TOKEN,
  MAPBOX_SECRET_TOKEN,
  ALGOLIA_ADMIN_KEY_LABELLED,
  DIGITALOCEAN_PAT,
  SNYK_TOKEN_LABELLED,
  HEROKU_API_KEY_LABELLED,
]
