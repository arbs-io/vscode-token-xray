# Token X-Ray

> [!NOTE]
> X-ray vision for tokens and secrets — locally inspect JWTs, SAML assertions, X.509 certificates, JWKs, OAuth / PASETO / Basic / AWS SigV4 tokens, OpenSSH and PGP material, OIDC discovery documents, HTTP signatures, cookies, and detect credentials in any source file. Runs entirely locally; no data leaves your machine.

![Visual Studio Marketplace Version](https://vsmarketplacebadges.dev/version-short/AndrewButson.vscode-token-xray.svg)
![Visual Studio Marketplace Installs](https://vsmarketplacebadges.dev/installs-short/AndrewButson.vscode-token-xray.svg)
![Visual Studio Marketplace Trending](https://vsmarketplacebadges.dev/trending-weekly/AndrewButson.vscode-token-xray.svg)
![Visual Studio Marketplace Rating](https://vsmarketplacebadges.dev/rating-star/AndrewButson.vscode-token-xray.svg)
[![GitHub issues](https://img.shields.io/github/issues/arbs-io/vscode-token-xray.svg)](https://github.com/arbs-io/vscode-token-xray/issues)

![.github/workflows/codeql-analysis](https://github.com/arbs-io/vscode-token-xray/actions/workflows/codeql-analysis.yml/badge.svg)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=arbs-io_vscode-token-xray&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=arbs-io_vscode-token-xray)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=arbs-io_vscode-token-xray&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=arbs-io_vscode-token-xray)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=arbs-io_vscode-token-xray&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=arbs-io_vscode-token-xray)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=arbs-io_vscode-token-xray&metric=bugs)](https://sonarcloud.io/summary/new_code?id=arbs-io_vscode-token-xray)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=arbs-io_vscode-token-xray&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=arbs-io_vscode-token-xray)

## What it inspects

Token X-Ray runs a registry of pure analyzers over every open document. Findings surface as **diagnostics** in the Problems panel, as **code lenses** above the matching lines (`Inspect`), as **hover previews**, as **inlay hints**, in a dedicated **Findings** view in the activity bar, on the **status bar**, and — for JWTs — in a dedicated **claimset viewer**.

| Analyzer                | Surface                                                                                                                                                                       |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **JWT / JWS / JWE**     | Decoded header + claimset, semantic highlighting, signature verification, expiry / audience / issuer checks, JWE shape detection                                              |
| **PASETO**              | v1–v4 detection; deprecation hint on v1/v2; encrypted-payload notice on `local` purpose                                                                                       |
| **SAML assertions**     | XML / base64 / DEFLATE+base64 decoding, Issuer, NameID, Conditions, AudienceRestriction, signature presence, encrypted-assertion detection                                    |
| **SAML 2.0 metadata**   | `EntityDescriptor` / `EntitiesDescriptor` parsing, IdP/SP role, NameIDFormats, ACS URLs, signing-cert expiry                                                                  |
| **X.509 certificates**  | PEM and base64-DER (`.cer` / `.crt`) decoding via Node's built-in `X509Certificate`; expired / weak-key / SHA-1 / self-signed / missing-SAN findings                          |
| **CSR**                 | `CERTIFICATE REQUEST` PEM blocks — subject, requested SANs, weak-key finding                                                                                                  |
| **JWK / JWKS**          | `kty` / `alg` / `kid` / `use` / key size; weak-key, deprecated-curve, private-material exposure, missing-`kid` findings                                                       |
| **OpenSSH public keys** | `ssh-rsa` / `ssh-ed25519` / `ecdsa-sha2-nistpXXX` / `ssh-dss`; weak DSA + weak RSA findings                                                                                   |
| **OpenPGP**             | Armored block detection (public / private / signature / message / signed-message); private-key-present and encrypted-message findings                                         |
| **OIDC discovery**      | `.well-known/openid-configuration` JSON — supported algs, scopes, endpoints; `alg=none`, weak HS256, non-HTTPS endpoint findings                                              |
| **HTTP signatures**     | Cavage draft and RFC 9421 — keyId, algorithm, covered components, signature; weak algorithm + future-`created` findings                                                       |
| **HTTP Basic auth**     | `Authorization: Basic <base64>` + labelled credential pairs — decoded username, masked password, plaintext-credential finding                                                 |
| **AWS SigV4 headers**   | `AWS4-HMAC-SHA256 Credential=…` — access key id, region, service; exposed-access-key + missing-host finding                                                                   |
| **OAuth opaque tokens** | Vendor token recognition: GitHub (`ghp_`, `ghs_`, `gho_`, `ghu_`, `ghr_`, `github_pat_`), Slack (`xox[bpoars]-`), Stripe (`sk_live_` / `pk_test_` / etc.) with severity tiers |
| **Cookies**             | RFC 6265 `Set-Cookie` parsing — missing `Secure` / `HttpOnly`, `SameSite=None` without `Secure`, no expiry, JWT-as-cookie, public-suffix `Domain`                             |
| **Secrets**             | 90+ inline credential rules across any text file — see below                                                                                                                  |

### Issuer recognition

When a JWT or OIDC config exposes an `iss`, Token X-Ray annotates the recognized identity provider:

- **Workforce / B2C**: Microsoft Entra ID v1 + v2, Microsoft B2C, Okta, Auth0, AWS Cognito, Ping Identity (PingOne + PingIdentity Cloud), ForgeRock, OneLogin, Keycloak, Salesforce
- **Consumer**: Google Accounts, Apple ID, Firebase, LinkedIn, Discord, Twitch
- **CIAM / developer**: Clerk, WorkOS, Frontegg, Descope
- **Workload identity**: GitHub Actions OIDC, GitLab OIDC, Cloudflare Access, SailPoint Identity Security Cloud

## Secret scanning

90+ vendor-specific secret rules ship out of the box. Hits report exact byte ranges so VS Code renders them as diagnostics on the precise characters.

| Category               | Vendors                                                                          |
| ---------------------- | -------------------------------------------------------------------------------- |
| **Cloud platforms**    | AWS, Azure, GCP, Cloudflare, DigitalOcean, Heroku                                |
| **Identity**           | Okta, Auth0, SailPoint, Cloudflare Access                                        |
| **AI providers**       | OpenAI, Anthropic, Hugging Face, Replicate                                       |
| **Databases**          | Postgres, MySQL, MongoDB, Redis, JDBC connection strings with embedded passwords |
| **Secrets management** | HashiCorp Vault, Terraform Cloud                                                 |
| **Source forges**      | GitHub, GitLab, Atlassian (Jira / Confluence)                                    |
| **Communications**     | Twilio, SendGrid, Mailgun, Telegram, Discord                                     |
| **Observability**      | Datadog, New Relic, Sentry, PagerDuty                                            |
| **Package registries** | npm, NuGet, PyPI, Docker Hub, JFrog Artifactory                                  |
| **CI/CD**              | CircleCI, Buildkite, Codecov                                                     |
| **Payments**           | Square, PayPal                                                                   |
| **Productivity**       | Notion, Linear, Figma, Postman, Asana, Monday                                    |
| **Misc**               | Mapbox, Algolia, Snyk                                                            |
| **Generic**            | PEM private keys, high-entropy strings, JWT-as-env-value                         |

Most rules mark a `sensitiveSpan` over just the secret value so the surrounding env var name / URL remains readable in diagnostics.

## Privacy

Every decoder, parser, and rule runs locally in the extension host. **No tokens, secrets, or document contents are transmitted off the machine.** Signature verification uses keys you configure locally — there is no JWKS network fetch.

## Features

### Inspect any token — claimset viewer

The claimset viewer renders each claim with its registered meaning (RFC 7519 + common public claims), IdP-specific annotations, and a findings banner (red / yellow / blue) at the top. Open it from the `Inspect` code lens above any detected token, the right-click menu, or the `Token X-Ray: Show rendered claimset` command.

![Claimset viewer](images/screenshot/vscode-token-xray-analysis.png)

### Findings activity-bar view

A dedicated **Token X-Ray** view container in the activity bar lists every detected token across open documents as an outline — analyzer kind, file:line, decoded sections, and findings. Click any node to reveal the source location.

<!-- TODO: capture screenshot — activity bar Findings tree expanded with a few token roots (JWT / x509 / secret) and their Header / Claims / Findings sub-nodes -->

![Findings tree](images/screenshot/vscode-token-xray-treeview.png)

### Diagnostics in the Problems panel

All findings stream into the Problems panel under the `tokenXray` source — errors / warnings / info entries with the rule id as the diagnostic code — so detections participate in your normal review flow.

<!-- TODO: capture screenshot — Problems panel filtered to source: tokenXray with mixed errors / warnings / info entries -->

![Diagnostics in Problems panel](images/screenshot/vscode-token-xray-problems.png)

### Other surfaces

- **JWT semantic highlighting** — coloured header / claimset / signature segments (plus JWE's encrypted-key / IV / ciphertext / auth-tag) via the VS Code Semantic Tokens API.
- **Hover preview** — hover any detected token in any file for a Markdown preview of its sections and findings.
- **Code lenses** — `Inspect …` lens above every detected token.
- **Inlay hints** — inline annotations like `[exp in 3d]`, `[expired]`, `[live]`, `[RSA-1024]`.
- **Status bar badge** — `🛡️ N errors, M warnings` for the active document; click to open the Problems panel.
- **Quick fixes** — Redact / Move-to-.env code actions on secret findings.
- **Outline + document links** — every detected token shows up as a document symbol; `iss` URL claims and finding `docUrl`s become clickable links.
- **JSON view** — `Token X-Ray: Show token as decoded JSON` opens the decoded payload as a regular JSON document.

## Commands

| Command                                   | Action                                                        |
| ----------------------------------------- | ------------------------------------------------------------- |
| `Token X-Ray: Inspect token`              | Inspect the token at the cursor (or the lens-triggered range) |
| `Token X-Ray: Show rendered claimset`     | Open the claimset viewer for the active JWT                   |
| `Token X-Ray: Show token as decoded JSON` | Open the decoded payload as a regular JSON document           |

The two preview commands are also available as title-bar buttons when the editor language is `jwt`.

## Suppressing findings

Three layers, in order of precedence (most-specific first):

### 1. Inline comments

```ts
// tokenxray-disable-next-line secret.aws.accessKeyId
const key = 'AKIAIOSFODNN7EXAMPLE'

# tokenxray-disable-file secret.openai.secretKey
```

`tokenxray-disable-next-line <ruleId>` skips findings on the next non-blank line. `tokenxray-disable-file <ruleId>` skips them for the entire file. Both accept comma-separated rule lists, and a `.*` suffix matches by prefix (`secret.*`).

### 2. `.tokenxrayignore`

A workspace-root file with `.gitignore`-style glob patterns. Path-level suppression — turns off **all** Token X-Ray findings for matching paths:

```
# .tokenxrayignore
**/fixtures/**
**/*.test.ts
!important.test.ts
```

### 3. Severity overrides

Tune individual rule severities (or turn rules off entirely) via the `tokenXray.ruleSeverity` setting:

```json
{
  "tokenXray.ruleSeverity": {
    "secret.aws.arn": "info",
    "jwt.alg.none": "error",
    "secret.openai.*": "off"
  }
}
```

## Configuration

| Setting                                 | Default   | Purpose                                                                                    |
| --------------------------------------- | --------- | ------------------------------------------------------------------------------------------ |
| `tokenXray.jwt.verifySignature`         | `false`   | Run signature verification in the claimset viewer                                          |
| `tokenXray.jwt.expectedIssuer`          | `""`      | If set, also assert `iss` equals this value                                                |
| `tokenXray.jwt.expectedAudience`        | `""`      | If set, also assert `aud` equals this value                                                |
| `tokenXray.jwt.keys`                    | `[]`      | Verification keys — JWK objects, `{ pem, alg, kid? }`, or `{ secret, alg, kid? }` for HMAC |
| `tokenXray.secrets.enabled`             | `true`    | Master switch for secret-rule findings                                                     |
| `tokenXray.secrets.exclude`             | `[]`      | Glob patterns to skip secret scanning for (independent of `.tokenxrayignore`)              |
| `tokenXray.secrets.maxFileSizeBytes`    | `1048576` | Skip secret scanning on documents larger than this (1 MiB default)                         |
| `tokenXray.secrets.codeActions.enabled` | `true`    | Enable the Redact / Move-to-.env quick fixes                                               |
| `tokenXray.inlayHints.enabled`          | `true`    | Show inline expiry / severity hints next to tokens                                         |
| `tokenXray.ruleSeverity`                | `{}`      | Per-rule severity overrides (`error` / `warning` / `info` / `off`)                         |
| `tokenXray.debug`                       | `false`   | Log scan counts and suppressions to the Token X-Ray output channel                         |

## Architecture

The codebase is layered so the analysis core stays pure and testable:

```
src/
  analyzers/    # pure detectors — no vscode imports
    jwt/  saml/  samlMetadata/  x509/  csr/  jwk/  sshKey/  pgp/
    oauth/  paseto/  basicAuth/  awsSigv4/  httpSignature/
    oidcDiscovery/  cookie/  secrets/
  core/         # AnalyzerRegistry + pure helpers (scanText, globMatch,
                # ignoreFile, severityOverrides, disableComments,
                # hover/inlayHints/documentLinks/documentSymbols/findingsTree)
  providers/    # vscode glue: diagnostics, code lenses, hovers, semantic tokens,
                # inlay hints, document links, document symbols, status bar,
                # findings tree, secret code actions, debug output channel
  panels/       # webview-based claimset viewer
  contexts/     # command registrations
webview/        # React app for the claimset viewer (own workspace)
```

`src/analyzers/**` and `src/core/**` must remain free of `vscode` imports — Vitest runs them with no mocks, and coverage thresholds are enforced (90% lines, 90% functions, 85% branches).

## Build

```bash
npm install
npm run build           # builds extension + webview workspaces
npm run typecheck       # tsc --noEmit
npm run test            # vitest run
npm run test:coverage   # enforce coverage thresholds
npm run esbuild         # bundle the extension (sourcemaps)
npm run deploy          # vsce publish
```

The CI workflow (`.github/workflows/vsix-package.yaml`) runs `typecheck` + `test` before packaging.

Sample fixtures live in `/sample` (JWTs, certificates, SAML responses, JWKs, cookie headers, secret-bearing text) and double as the test corpus for the analyzers.

## How can I help?

If you find Token X-Ray useful, a rating on the Visual Studio Marketplace makes a real difference. Bugs and feature requests are very welcome on the GitHub issue tracker, and pull requests even more so.

This is a personal passion project — sponsoring on GitHub helps keep time carved out for it.

---

<sub>Suggested GitHub repository description: **X-ray vision for tokens and secrets in VS Code — locally inspect JWTs, SAML, X.509, JWKs, OAuth, PASETO, SSH keys, PGP, cookies, and detect 90+ vendor credentials in any file.**</sub>
