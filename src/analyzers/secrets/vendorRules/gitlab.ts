import { SecretRule } from '../types'

// GitLab issues several token forms with distinct fixed prefixes
// (https://docs.gitlab.com/ee/security/token_overview.html). Each token
// is anchored by negative lookbehind/lookahead against the identifier
// charset `[A-Za-z0-9_-]` so an identifier such as `x_glpat-…` (a
// variable name) never extracts a token out of a longer word. The body
// charsets follow the GitLab token grammar — PAT / runner / deploy /
// feature-flag / CI tokens accept base64url-ish `[A-Za-z0-9_-]`; OAuth
// access tokens are 64 lowercase hex characters.

const PAT: SecretRule = {
  id: 'secret.gitlab.pat',
  vendor: 'gitlab',
  name: 'GitLab personal access token (glpat-…)',
  pattern: /(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'GitLab personal access token. Grants API + repo access scoped to the issuing user — revoke immediately if leaked.',
  docUrl: 'https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html',
}

const OAUTH: SecretRule = {
  id: 'secret.gitlab.oauth',
  vendor: 'gitlab',
  name: 'GitLab OAuth access token (gloas-…)',
  pattern: /(?<![A-Za-z0-9_-])gloas-[a-f0-9]{64}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'GitLab OAuth 2.0 access token (64 hex chars). Confers the scopes granted to the OAuth application — revoke immediately if leaked.',
  docUrl: 'https://docs.gitlab.com/ee/api/oauth2.html',
}

const RUNNER_TOKEN: SecretRule = {
  id: 'secret.gitlab.runnerToken',
  vendor: 'gitlab',
  name: 'GitLab runner authentication token (glrt-…)',
  pattern: /(?<![A-Za-z0-9_-])glrt-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'GitLab runner authentication token. Anyone with the value can register a malicious runner that picks up CI jobs for the project / group — revoke immediately if leaked.',
  docUrl: 'https://docs.gitlab.com/ee/security/token_overview.html#runner-authentication-tokens',
}

const DEPLOY_TOKEN: SecretRule = {
  id: 'secret.gitlab.deployToken',
  vendor: 'gitlab',
  name: 'GitLab deploy token (gldt-…)',
  pattern: /(?<![A-Za-z0-9_-])gldt-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'GitLab deploy token. Grants read/write access to a project repository or registry packages — revoke immediately if leaked.',
  docUrl: 'https://docs.gitlab.com/ee/user/project/deploy_tokens/',
}

const FEATURE_FLAG_CLIENT_TOKEN: SecretRule = {
  id: 'secret.gitlab.featureFlagClientToken',
  vendor: 'gitlab',
  name: 'GitLab feature flag client token (glffct-…)',
  pattern: /(?<![A-Za-z0-9_-])glffct-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'GitLab feature flag client token. Anyone with the value can read feature flag state via the Unleash-compatible API — rotate immediately if leaked.',
  docUrl: 'https://docs.gitlab.com/ee/operations/feature_flags.html',
}

const CICD_JOB_TOKEN: SecretRule = {
  id: 'secret.gitlab.cicdJobToken',
  vendor: 'gitlab',
  name: 'GitLab CI/CD job token (glcbt-…)',
  pattern: /(?<![A-Za-z0-9_-])glcbt-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'GitLab CI/CD job token (CI_JOB_TOKEN). Authenticates to the GitLab API as the running job and inherits its project permissions — never commit; never log.',
  docUrl: 'https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html',
}

export const GITLAB_SECRET_RULES: SecretRule[] = [
  PAT,
  OAUTH,
  RUNNER_TOKEN,
  DEPLOY_TOKEN,
  FEATURE_FLAG_CLIENT_TOKEN,
  CICD_JOB_TOKEN,
]
