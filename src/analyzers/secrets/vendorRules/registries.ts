import { SecretRule } from '../types'

// Package-registry token formats: npm publish tokens, NuGet API keys, PyPI
// macaroon upload tokens, Docker Hub personal access tokens, JFrog Artifactory
// access tokens. Each pattern is anchored against the surrounding identifier
// charset with negative lookbehind / lookahead so an identifier such as
// `x_npm_…` or `_npm_…` (a variable name) cannot accidentally extract a token
// out of a longer word. Body charsets match the public token grammar for each
// registry — npm and JFrog use bare `[A-Za-z0-9]`; NuGet, PyPI, and Docker Hub
// use the base64url-ish `[A-Za-z0-9_-]` alphabet, so their anchors include the
// `_-` chars to avoid false splits inside a longer token-shaped run.

// npm access tokens are 39 characters total: the literal `npm_` prefix
// followed by 36 alnum characters (no `_`/`-`). Authenticated as the issuing
// user — any holder can publish / yank packages on their behalf.
const NPM_ACCESS_TOKEN: SecretRule = {
  id: 'secret.npm.accessToken',
  vendor: 'npm',
  name: 'npm access token (npm_…)',
  pattern: /(?<!\w)npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'npm access token. Grants publish/yank rights for packages owned by the issuing user — revoke immediately if leaked.',
  docUrl: 'https://docs.npmjs.com/about-access-tokens',
}

// NuGet API keys are 46 characters: literal `oy2` prefix + 43 base64url
// characters. The negative lookbehind/lookahead includes `_-` so the match
// cannot start or end inside a longer base64url body.
const NUGET_API_KEY: SecretRule = {
  id: 'secret.nuget.apiKey',
  vendor: 'nuget',
  name: 'NuGet API key (oy2…)',
  pattern: /(?<![A-Za-z0-9_-])oy2[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'NuGet API key. Grants push rights on nuget.org for packages owned by the issuing account — revoke immediately if leaked.',
  docUrl: 'https://learn.microsoft.com/nuget/nuget-org/scoped-api-keys',
}

// PyPI macaroon upload tokens carry the literal `pypi-AgEIcHlwaS5vcmc` prefix
// (the base64url encoding of the macaroon header for `pypi.org`) followed by
// a long base64url body. Real tokens are well over 100 characters; we require
// at least 100 body chars to anchor the match and avoid grabbing truncated
// fragments.
const PYPI_MACAROON_TOKEN: SecretRule = {
  id: 'secret.pypi.macaroonToken',
  vendor: 'pypi',
  name: 'PyPI macaroon upload token (pypi-AgEIcHlwaS5vcmc…)',
  pattern: /(?<![A-Za-z0-9_-])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{100,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'PyPI macaroon upload token. Authorises uploads to pypi.org for the issuing account / project — revoke immediately if leaked.',
  docUrl: 'https://pypi.org/help/#apitoken',
}

// Docker Hub personal access tokens (PATs) carry the literal `dckr_pat_`
// prefix. The body alphabet is base64url-ish; we require at least 20 body
// chars so a bare `dckr_pat_` (or a very short fragment) cannot match.
const DOCKER_HUB_PAT: SecretRule = {
  id: 'secret.dockerHub.pat',
  vendor: 'dockerHub',
  name: 'Docker Hub personal access token (dckr_pat_…)',
  pattern: /(?<![A-Za-z0-9_-])dckr_pat_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Docker Hub personal access token. Grants registry pull/push rights for the issuing account — revoke immediately if leaked.',
  docUrl: 'https://docs.docker.com/security/for-developers/access-tokens/',
}

// JFrog Artifactory access tokens carry the literal `AKCp` prefix + 67
// alphanumeric characters (no `_`/`-`). The negative lookbehind/lookahead
// restricts the surrounding charset to `[A-Za-z0-9]` so a token cannot be
// extracted from a longer identifier such as `xAKCp…`.
const JFROG_ACCESS_TOKEN: SecretRule = {
  id: 'secret.jfrog.accessToken',
  vendor: 'jfrog',
  name: 'JFrog Artifactory access token (AKCp…)',
  pattern: /(?<![A-Za-z0-9])AKCp[A-Za-z0-9]{67}(?![A-Za-z0-9])/g,
  severity: 'error',
  description:
    'JFrog Artifactory access token. Authenticates against the Artifactory REST / repository APIs as the issuing identity — revoke immediately if leaked.',
  docUrl: 'https://jfrog.com/help/r/jfrog-platform-administration-documentation/access-tokens',
}

export const REGISTRIES_SECRET_RULES: SecretRule[] = [
  NPM_ACCESS_TOKEN,
  NUGET_API_KEY,
  PYPI_MACAROON_TOKEN,
  DOCKER_HUB_PAT,
  JFROG_ACCESS_TOKEN,
]
