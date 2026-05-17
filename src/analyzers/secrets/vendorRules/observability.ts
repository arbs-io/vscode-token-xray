import { SecretRule } from '../types'

// Helper: find the value half of a labelled `KEY=<value>` / `KEY: <value>`
// pattern and return its absolute span within the matched raw string. Mirrors
// the implementation used by the other labelled-token vendor rules.
const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// Datadog API keys are 32 lowercase-hex characters and only appear in the
// wild adjacent to an explicit env-style label (DD_API_KEY / DATADOG_API_KEY).
// Without the label a 32-hex run is indistinguishable from countless other
// hashes so we deliberately only surface the labelled form.
const DATADOG_API_KEY_LABELLED: SecretRule = {
  id: 'secret.datadog.apiKeyLabelled',
  vendor: 'datadog',
  name: 'Datadog API key (env-labelled DD_API_KEY=/DATADOG_API_KEY=)',
  pattern: /(?:DD_API_KEY|DATADOG_API_KEY|dd_api_key|datadog_api_key|datadogApiKey|ddApiKey)["']?\s*[:=]\s*["']?[a-f0-9]{32}["']?/g,
  severity: 'error',
  description:
    'Datadog API key referenced via env var. Grants ingestion / submission access for the issuing Datadog org — rotate immediately if leaked.',
  docUrl: 'https://docs.datadoghq.com/account_management/api-app-keys/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-f0-9]{32})/),
}

// Datadog APP (application) keys are 40 lowercase-hex characters and grant
// API-level access scoped to the issuing user — strictly more powerful than
// an API key. Same env-label-only stance as above.
const DATADOG_APP_KEY_LABELLED: SecretRule = {
  id: 'secret.datadog.appKeyLabelled',
  vendor: 'datadog',
  name: 'Datadog APP key (env-labelled DD_APP_KEY=/DATADOG_APP_KEY=)',
  pattern: /(?:DD_APP_KEY|DATADOG_APP_KEY|DD_APPLICATION_KEY|DATADOG_APPLICATION_KEY|dd_app_key|datadog_app_key|datadogAppKey|ddAppKey)["']?\s*[:=]\s*["']?[a-f0-9]{40}["']?/g,
  severity: 'error',
  description:
    'Datadog application (APP) key referenced via env var. Grants user-level API access to the issuing Datadog org — rotate immediately if leaked.',
  docUrl: 'https://docs.datadoghq.com/account_management/api-app-keys/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([a-f0-9]{40})/),
}

// New Relic user keys carry the literal `NRAK-` prefix followed by 27
// uppercase-alphanumeric characters. The negative lookbehind/lookahead anchors
// the match against identifier context so a longer label like `_NRAK-…` or a
// trailing alnum run cannot accidentally extract a key.
const NEW_RELIC_USER_KEY: SecretRule = {
  id: 'secret.newRelic.userKey',
  vendor: 'newRelic',
  name: 'New Relic user key (NRAK-…)',
  pattern: /(?<![A-Za-z0-9])NRAK-[A-Z0-9]{27}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'New Relic user API key (NRAK-…). Grants user-level access to the issuing New Relic account — rotate immediately if leaked.',
  docUrl: 'https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/',
}

// New Relic ingest license keys use the `NRAA-` prefix with the same 27-char
// uppercase-alphanumeric body shape as user keys. Treated as a hard error
// because possession allows arbitrary metric/log ingestion against the org.
const NEW_RELIC_INGEST_KEY: SecretRule = {
  id: 'secret.newRelic.ingestKey',
  vendor: 'newRelic',
  name: 'New Relic ingest license key (NRAA-…)',
  pattern: /(?<![A-Za-z0-9])NRAA-[A-Z0-9]{27}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'New Relic ingest license key (NRAA-…). Permits arbitrary metric / log / event ingestion against the issuing account — rotate immediately if leaked.',
  docUrl: 'https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/',
}

// New Relic license keys use the `NRAL-` prefix. Same identifier-anchoring
// strategy and same severity stance as the other New Relic surfaces.
const NEW_RELIC_LICENSE_KEY: SecretRule = {
  id: 'secret.newRelic.licenseKey',
  vendor: 'newRelic',
  name: 'New Relic license key (NRAL-…)',
  pattern: /(?<![A-Za-z0-9])NRAL-[A-Z0-9]{27}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'New Relic license key (NRAL-…). Authenticates agent / SDK telemetry against the issuing account — rotate immediately if leaked.',
  docUrl: 'https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/',
}

// Sentry DSNs look like `https://<32-hex>@(?:o\d+\.)?(?:ingest\.)?sentry.io/<projectId>`.
// The 32-hex portion is the project's public auth key and is the secret half
// of the DSN — the rest is the public host/project identifier. We anchor the
// match on the literal scheme + host so unrelated 32-hex strings cannot match,
// and `sensitiveSpan` marks just the 32-hex key portion.
const SENTRY_DSN: SecretRule = {
  id: 'secret.sentry.dsn',
  vendor: 'sentry',
  name: 'Sentry DSN (https://<key>@…sentry.io/<project>)',
  pattern: /https:\/\/[a-f0-9]{32}@(?:o\d+\.)?(?:ingest\.)?sentry\.io\/\d+/g,
  severity: 'error',
  description:
    'Sentry DSN. The 32-hex segment is the project public auth key and lets any holder submit events (and read minidumps in some configs) to the issuing Sentry project — rotate immediately if leaked.',
  docUrl: 'https://docs.sentry.io/product/sentry-basics/dsn-explainer/',
  // Mark only the 32-hex secret half of the DSN. The host portion is public.
  sensitiveSpan: (raw) => {
    const m = /https:\/\/([a-f0-9]{32})@/.exec(raw)
    if (!m) return { start: 0, end: raw.length }
    const start = raw.indexOf(m[1])
    return { start, end: start + m[1].length }
  },
}

// PagerDuty REST API tokens are 20 characters from the `[A-Za-z0-9_+-]`
// alphabet. Like the Datadog keys, the body shape on its own is too generic to
// detect safely — we only flag the env-labelled `PAGERDUTY_TOKEN=` form so a
// random 20-char identifier in source isn't misclassified.
const PAGERDUTY_TOKEN_LABELLED: SecretRule = {
  id: 'secret.pagerduty.tokenLabelled',
  vendor: 'pagerduty',
  name: 'PagerDuty API token (env-labelled PAGERDUTY_TOKEN=)',
  pattern: /(?:PAGERDUTY_TOKEN|PAGER_DUTY_TOKEN|pagerduty_token|pagerDutyToken)["']?\s*[:=]\s*["']?[A-Za-z0-9_+-]{20}["']?/g,
  severity: 'error',
  description:
    'PagerDuty API token referenced via env var. Grants REST API access to the issuing PagerDuty account — rotate immediately if leaked.',
  docUrl: 'https://developer.pagerduty.com/docs/rest-api-v2/authentication/',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_+-]{20})/),
}

export const OBSERVABILITY_SECRET_RULES: SecretRule[] = [
  DATADOG_API_KEY_LABELLED,
  DATADOG_APP_KEY_LABELLED,
  NEW_RELIC_USER_KEY,
  NEW_RELIC_INGEST_KEY,
  NEW_RELIC_LICENSE_KEY,
  SENTRY_DSN,
  PAGERDUTY_TOKEN_LABELLED,
]
