import { SecretRule } from '../types'

// CI/CD service tokens: CircleCI personal access tokens, Buildkite agent &
// API tokens, Codecov upload tokens. Each non-labelled pattern is anchored
// against the surrounding identifier charset with negative lookbehind /
// lookahead so a token cannot be accidentally extracted from a longer
// identifier (e.g. `xCCIPAT_…` or `_bka_…`). The Codecov upload token is
// only flagged in its labelled `CODECOV_TOKEN=<uuid>` env form — a bare UUID
// is indistinguishable from countless other identifiers and would generate
// far too much noise without the label.

// Helper: find the value half of a labelled `KEY=<value>` / `KEY: <value>`
// pattern and return its absolute span within the matched raw string.
const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// CircleCI personal access tokens carry the literal `CCIPAT_` prefix
// followed by 40 or more base64url-ish characters. The negative
// lookbehind/lookahead anchors against `[A-Za-z0-9_-]` so the match cannot
// start or end inside a longer base64url body.
const CIRCLECI_PAT: SecretRule = {
  id: 'secret.circleci.pat',
  vendor: 'circleci',
  name: 'CircleCI personal access token (CCIPAT_…)',
  pattern: /(?<![A-Za-z0-9_-])CCIPAT_[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'CircleCI personal access token. Grants CircleCI API access as the issuing user — revoke immediately if leaked.',
  docUrl: 'https://circleci.com/docs/managing-api-tokens/',
}

// Buildkite agent tokens carry the literal `bka_` prefix followed by
// exactly 52 alphanumeric characters (no `_`/`-`). Used by Buildkite agents
// to register with the control plane.
const BUILDKITE_AGENT_TOKEN: SecretRule = {
  id: 'secret.buildkite.agentToken',
  vendor: 'buildkite',
  name: 'Buildkite agent token (bka_…)',
  pattern: /(?<![A-Za-z0-9])bka_[A-Za-z0-9]{52}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Buildkite agent registration token. Allows any holder to register an agent and claim jobs on behalf of the issuing organisation — revoke immediately if leaked.',
  docUrl: 'https://buildkite.com/docs/agent/v3/tokens',
}

// Buildkite API tokens carry the literal `bkua_` prefix followed by
// exactly 40 alphanumeric characters (no `_`/`-`).
const BUILDKITE_API_TOKEN: SecretRule = {
  id: 'secret.buildkite.apiToken',
  vendor: 'buildkite',
  name: 'Buildkite API access token (bkua_…)',
  pattern: /(?<![A-Za-z0-9])bkua_[A-Za-z0-9]{40}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'Buildkite API access token. Grants REST API access against the issuing user / organisation — revoke immediately if leaked.',
  docUrl: 'https://buildkite.com/docs/apis/managing-api-tokens',
}

// Codecov upload tokens are UUID-shaped (8-4-4-4-12 lowercase hex with
// hyphens, 36 chars total). A bare UUID is too generic to flag safely so
// we only match the labelled `CODECOV_TOKEN=<uuid>` env form. The
// sensitiveSpan covers just the UUID half of the match.
const CODECOV_UPLOAD_TOKEN_LABELLED: SecretRule = {
  id: 'secret.codecov.uploadTokenLabelled',
  vendor: 'codecov',
  name: 'Codecov upload token (env-labelled CODECOV_TOKEN=)',
  pattern: /(?:CODECOV_TOKEN|CODECOV_UPLOAD_TOKEN|codecov_token|codecovToken)["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?/g,
  severity: 'error',
  description:
    'Codecov upload token (UUID) referenced via env var. Grants coverage upload rights on behalf of the issuing repository — rotate immediately if leaked.',
  docUrl: 'https://docs.codecov.com/docs/codecov-uploader',
  sensitiveSpan: (raw) =>
    sensitiveAfterDelimiter(
      raw,
      /[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/
    ),
}

export const CI_SECRET_RULES: SecretRule[] = [
  CIRCLECI_PAT,
  BUILDKITE_AGENT_TOKEN,
  BUILDKITE_API_TOKEN,
  CODECOV_UPLOAD_TOKEN_LABELLED,
]
