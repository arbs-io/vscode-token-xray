# Changelog

All notable changes to Token X-Ray are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-05-17

### Added — Token & cryptographic formats

- JWT / JWS / JWE — decoded header + claimset, semantic highlighting, signature verification (HS/RS/ES via `jose`), JWE 5-segment detection with encrypted-payload notice, IdP issuer recognition (Entra v1/v2, Okta, Auth0, Cognito, Cloudflare Access, SailPoint, Google, Firebase, GitHub Actions OIDC, GitLab + 14 more via `idp-issuer-expanded`: Ping Identity, ForgeRock, OneLogin, Keycloak, Salesforce, Apple ID, Microsoft B2C, Clerk, WorkOS, Frontegg, Descope, Twitch, LinkedIn, Discord)
- SAML 2.0 assertions (XML / base64 / DEFLATE+base64) — signature, validity window, audience, encrypted-assertion findings
- SAML 2.0 metadata (EntityDescriptor / EntitiesDescriptor) — entityID, IdP/SP roles, NameIDFormats, AssertionConsumerService URLs, signing-cert expiry findings
- X.509 certificates (PEM + DER via `.cer`/`.crt`/`.der`) — expired / weak-key / weak-signature / self-signed / missing-SAN findings
- JWK / JWKS — weak-key, deprecated-curve, private-material-leak, missing-kid findings
- OAuth opaque tokens (GitHub, Slack, Stripe) with live / test / publishable severity tiers
- HTTP cookies (Set-Cookie / Cookie) — Secure, HttpOnly, SameSite, expiry, JWT-as-cookie, public-suffix Domain findings
- PASETO v1–v4 — deprecated-version (v1/v2) and local-purpose findings
- HTTP Basic Authorization headers — masked credentials, plaintext finding
- AWS Signature v4 Authorization headers — exposed access key, session-token, missing-host signed-header findings
- Certificate Signing Requests (CSRs, PKCS#10) — subject DN, RSA modulus bit-count, EC curve via OID table, SAN extraction, weak-RSA / missing-SAN findings
- OpenSSH public keys (RSA, ECDSA nistp{256,384,521}, Ed25519, DSS) — wire-format parser, weak-DSA / weak-RSA findings + ECDSA curve info
- OpenPGP armored blocks (PUBLIC/PRIVATE KEY BLOCK, SIGNATURE, MESSAGE, SIGNED MESSAGE) — private-key-present, encrypted-message, malformed-armor findings
- OIDC discovery documents — issuer, jwks_uri, supported algs / scopes / response types; algs-none-allowed, weak-HS256-allowed, endpoint-not-https findings
- HTTP signatures (Cavage draft and RFC 9421) — weak-algorithm, missing-algorithm, future-created findings

### Added — Secret scanning rules

- AWS access keys (AKIA / ASIA), labelled `AWS_SECRET_ACCESS_KEY`, ARNs with doc-example suppression
- GCP service-account JSON, `AIza` API keys, OAuth client_secret + refresh + access (`ya29`) tokens
- Azure storage AccountKey / SharedAccessKey / SAS query tokens, `AZURE_CLIENT_SECRET`, subscription + tenant IDs
- Okta SSWS header tokens, labelled `OKTA_API_TOKEN` / `OKTA_CLIENT_SECRET`
- Cloudflare global API key, scoped API tokens, Access client_id/client_secret, Tunnel tokens
- Auth0 — labelled `AUTH0_CLIENT_SECRET`, Management API JWT, `AUTH0_DOMAIN` tenant exposure
- SailPoint — labelled client_id / client_secret / tenant URL (SAIL_ / SAILPOINT_ / IDN_ / ISC_ prefixes + camelCase)
- GitHub — labelled `GITHUB_CLIENT_SECRET` / `GITHUB_WEBHOOK_SECRET` / `GITHUB_APP_PRIVATE_KEY_PATH` (token-form GitHub credentials remain in the OAuth analyzer to avoid duplicate diagnostics)
- AI providers — OpenAI (`sk-`, `sk-proj-`), Anthropic (`sk-ant-api03-` / `sk-ant-admin01-`), Hugging Face (`hf_`), Replicate (`r8_`), with labelled env forms
- Database connection strings (Postgres, MySQL, MongoDB + mongodb+srv, Redis + rediss, JDBC) with sensitiveSpan over the password substring only
- HashiCorp Vault (`hvs.` service, `hvr.` root) + labelled `VAULT_TOKEN=`; Terraform Cloud user tokens + labelled `TF_TOKEN_app_terraform_io=`
- Atlassian Cloud API tokens (`ATATT3xFfGF0…`), labelled `JIRA_API_TOKEN` / `CONFLUENCE_API_TOKEN` / `ATLASSIAN_OAUTH_CLIENT_SECRET`
- GitLab tokens — `glpat-`, `gloas-`, `glrt-`, `gldt-`, `glffct-`, `glcbt-`
- Communications APIs — Twilio (Account SID, API Key SID, labelled auth token), SendGrid, Mailgun, Telegram bot, Discord bot
- Observability — Datadog (API + APP keys), New Relic (NRAK / NRAA / NRAL), Sentry DSN, PagerDuty
- Package registries — npm, NuGet, PyPI macaroon, Docker Hub, JFrog Artifactory
- CI/CD — CircleCI, Buildkite (agent + API), Codecov upload token
- Payments — Square (access / app secret / app id), PayPal long-form access token
- Productivity — Notion, Linear (api + OAuth), Figma, Postman, Asana, Monday
- Mapbox (pk / sk), Algolia admin, DigitalOcean (`dop_v1_`), Snyk, Heroku
- Generic — PEM private keys, high-entropy detector (info, requires ≥3 char classes), JWT-in-`.env` detector (warning), with cross-rule dedup so info hits never double-flag higher-severity ranges

### Added — VS Code surface integrations

- Hover preview across all analyzers (`buildHoverMarkdown` renderer over every analyzer kind) for file + untitled documents; legacy JOSE webview hover preserved for `jwt`-language files
- Inlay hints for token expiry (`[exp in 3d]` / `[expired]`), x509 key size (`[RSA-1024]`), x509 + SAML-metadata expiry markers, OAuth live-environment, secret markers
- Document links for `iss` claim URLs and finding `docUrl`s
- Document symbols listing detected tokens in Outline (one per hit, per-analyzer SymbolKind)
- Activity-bar Findings tree view grouped by analyzer with reveal-in-editor on click, refreshed on diagnostic changes
- Status bar badge showing the active document's finding counts (errors + warnings, info hidden when higher-severity present); click opens Problems panel
- Code actions to Redact (`***`) or Move-to-`.env.example` for secret findings
- Diagnostics across all text documents with `tokenXray.secrets.{enabled,exclude,maxFileSizeBytes}` controls
- JWT diagnostics in the Problems panel and findings banner in the JWT webview
- JWT CodeLens ("Inspect JWT") that scans any open document for JWT-shaped strings
- Notebook cell scanning (`.ipynb`) — each cell flows through the diagnostics pipeline as its own `TextDocument` (via `vscode-notebook-cell` scheme), with parent-notebook anchoring for exclude globs and `.tokenxrayignore`
- Debug output channel ("Token X-Ray") logging per-scan counts and per-suppression events with ISO-8601 timestamps

### Added — Configuration

- `tokenXray.secrets.enabled` (default true)
- `tokenXray.secrets.exclude` (glob array)
- `tokenXray.secrets.maxFileSizeBytes` (default 1 MiB)
- `tokenXray.secrets.codeActions.enabled` (default true)
- `tokenXray.inlayHints.enabled` (default true)
- `tokenXray.ruleSeverity` (per-rule severity overrides; `error` / `warning` / `info` / `off`, supports `id.*` wildcards with longest-prefix-wins)
- `tokenXray.debug` (output-channel logging, default false)
- `tokenXray.jwt.verifySignature`, `tokenXray.jwt.expectedIssuer`, `tokenXray.jwt.expectedAudience`, `tokenXray.jwt.keys` (opt-in JWT signature verification with PEM / JWK / symmetric keys)
- `.tokenxrayignore` workspace file for path-level suppression (gitignore-style globs with last-matching-rule-wins negation; suppresses ALL findings, not just secrets)
- Inline disable comments: `// tokenxray-disable-next-line <ruleId>` / `# tokenxray-disable-next-line <ruleId>` and file-scoped `tokenxray-disable-file <ruleId>`, with `prefix.*` wildcards and `--` trailing remarks

### Changed

- Renamed from "JWT Decoder" to "Token X-Ray"
- Repository moved to `vscode-token-xray`; `package.json` `repository.url` updated to match the new git remote
- Findings tree view: every analyzer kind now has its own codicon (key, shield, verified, lock, cloud, gist-secret, terminal, …) tinted to the worst severity. Section groups (`JOSE Header`, `Claims`, `Certificate`, `Subject & Key`, etc.) gained per-title icons; finding rows show a coloured severity icon and a compact `1E 2W 3I` badge on the parent token row.
- Tightened the JWT claimset webview CSP — `img-src` now restricted to `cspSource + data:` (was `*`); `style-src 'unsafe-inline'` retained intentionally for the React inline-style tree and documented in-source.
- Marketplace metadata: added `keywords` and moved `categories` to `["Linters","Other"]` so the listing surfaces on security/linter searches.

### Added (1.2)

- **`tokenXray.respectGitignore`** (default `true`) — workspace `.gitignore` patterns (root + nested) are merged with `.tokenxrayignore` so gitignored files (e.g. `.env`, `secrets/`, `dist/`) are skipped by every analyzer. Nested `.gitignore` files are applied relative to their own directory, matching `git` precedence.
- **`tokenXray.scan.debounceMs`** (default `250`, range `0–2000`) — user-tunable trailing-edge debounce on text-change events. Lower for snappier feedback on small files, higher to throttle CPU on large files.
- Per-document trailing-edge debounce on `onDidChangeTextDocument` so a typing burst resolves to a single trailing scan instead of one scan per keystroke.
- Binary-content short-circuit: any document containing a NUL byte in the first 8 KiB is skipped by both the cache and the diagnostics pass, eliminating high-entropy noise on accidentally-opened binaries.
- Cooperative cancellation via `AbortSignal` plumbed through `scanText` and `diagnosticsAcrossRegistry`; a superseded scan now stops mid-registry-walk instead of running to completion before its result is discarded.
- `ScanCache` now exposes an optional `onError` callback wired to the debug output channel — analyzer-thrown errors are no longer silently swallowed when `tokenXray.debug` is on.
- `tokenXray.jwt.keys` entries that don't parse as a recognised shape are reported via a one-shot warning toast (with an **Open Settings** button) and a line in the debug channel; per-config-revision dedup means editing one bad entry doesn't re-toast on every keystroke.
- Webview React tree migrated to a CSS module (`webview/src/App.module.css`); no remaining `style={}` props in our code. `'unsafe-inline'` is retained in `style-src` only because the deprecated `@vscode/webview-ui-toolkit` web components still need it (documented in-source for future toolkit migration).
- Shared path utilities (`src/utils/workspacePath.ts`) extracted from the diagnostics and tree-view providers (`notebookFileUri`, `effectiveUri`, `workspaceRelativeFilename`, `workspaceRelativePathForIgnore`, `fallbackDisplayLabel`).

### Infrastructure

- Vitest test suite (1783+ tests, 90/85/90/90 statements/branches/functions/lines coverage thresholds enforced); new coverage for `secretCodeActionsProvider`, change-event debouncing, binary detection, JWT key-loader detailed errors, ignore-source matcher (nested `.gitignore`), workspace-path utils, hover provider, code-lens / document-link / document-symbol / inlay-hint smoke tests, and scan cancellation.
- GitHub Actions workflow bumped to Node 22 (Active LTS) and now runs `npm run test:coverage`, uploads the coverage report as a CI artifact, and runs `npm run check-version`, `npm run typecheck` on every matrix OS before `vsce package`. CodeQL workflow updated to v3 actions and the `javascript-typescript` language pack.

[1.2.0]: https://github.com/arbs-io/vscode-token-xray/releases/tag/v1.2.0
