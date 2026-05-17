# Token X-Ray

> X-ray vision for tokens and secrets — inspect JWTs, SAML assertions, X.509 certificates, JWKs, OAuth tokens, and cookies, and detect credentials in any source file. Runs entirely locally; no data leaves your machine.

![Visual Studio Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/AndrewButson.vscode-token-xray)
![Visual Studio Marketplace Installs](https://img.shields.io/visual-studio-marketplace/i/AndrewButson.vscode-token-xray)
![Visual Studio Marketplace Rating](https://img.shields.io/visual-studio-marketplace/r/AndrewButson.vscode-token-xray)

## What it inspects

Token X-Ray runs a registry of pure analyzers over every open document. Findings surface in the **Problems panel** as diagnostics, as **code lenses** above the matching lines (`Inspect`), and — for JWTs — in a dedicated **claimset viewer**.

| Analyzer | Surface |
| --- | --- |
| **JWT / JWS / JWE** | Decoded header + claimset, semantic highlighting, signature verification, expiry / audience / issuer checks, JWE shape detection |
| **IdP recognition** | `iss`-based annotations for Entra ID v1/v2, Okta, Auth0, Cognito, Cloudflare Access, SailPoint, Google, Firebase, GitHub Actions OIDC, GitLab OIDC |
| **SAML** | XML / base64 / DEFLATE+base64 decoding, Issuer, NameID, Conditions (NotBefore / NotOnOrAfter), AudienceRestriction, signature presence, encrypted-assertion detection |
| **X.509** | PEM decoding via Node's built-in `X509Certificate` — Subject, Issuer, SAN, Validity, KeyUsage, signature algorithm; findings for expired, weak key (RSA<2048), SHA-1 signature, self-signed, missing SAN |
| **JWK / JWKS** | `kty` / `alg` / `kid` / `use` / key size; findings for weak key, deprecated curve, private material exposure, missing `kid` |
| **OAuth tokens** | Vendor token recognition: GitHub (`ghp_`, `ghs_`, `gho_`, `ghu_`, `ghr_`, `github_pat_`), Slack (`xox[bpoars]-`), Stripe (`sk_live_` / `pk_test_` / etc.) with severity tiers |
| **Cookies** | RFC 6265 `Set-Cookie` parsing; findings for missing `Secure`, missing `HttpOnly`, `SameSite=None` without `Secure`, no expiry, JWT-as-cookie, public-suffix `Domain` |
| **Secrets** | Inline credential scanning across any text file — see below |

## Secret scanning

The secret scanner is a pure detector (no `vscode` imports) shipping vendor rule sets:

- **PEM private keys** — `RSA`, `EC`, `OPENSSH`, `DSA`
- **AWS** — `AKIA…` (error) / `ASIA…` (warning) keys, labelled `AWS_SECRET_ACCESS_KEY`, ARNs (with doc-example suppression)
- **GCP** — service-account JSON marker, `AIza…` API keys, OAuth client_secret / refresh / `ya29.` access tokens
- **Azure** — storage `AccountKey`, `SharedAccessKey`, SAS query tokens, `AZURE_CLIENT_SECRET`, subscription / tenant IDs
- **Cloudflare** — global API key (`X-Auth-Key`), scoped API tokens, Access client_id / client_secret, Tunnel tokens
- **Okta** — `Authorization: SSWS …` headers, labelled `OKTA_API_TOKEN` / `OKTA_CLIENT_SECRET`
- **Auth0** — labelled `AUTH0_CLIENT_SECRET`, Management API tokens, `AUTH0_DOMAIN` tenant exposure
- **SailPoint** — `SAIL_` / `SAILPOINT_` / `IDN_` / `ISC_` prefixed client_id / client_secret / tenant URL
- **GitHub** — labelled `GITHUB_CLIENT_SECRET` / `GITHUB_WEBHOOK_SECRET` / app private-key paths (token forms are handled by the OAuth analyzer to avoid duplicate diagnostics)

Each hit reports a byte range so VS Code can render it as a diagnostic on the exact characters.

## Privacy

Every decoder, parser, and rule runs locally in the extension host. **No tokens, secrets, or document contents are transmitted off the machine.** Signature verification uses keys you configure locally — there is no JWKS network fetch (yet).

## JWT semantic highlighting

Token X-Ray registers a `jwt` language and uses the VS Code Semantic Tokens API to colour the header, claimset, and signature sections of a JWS distinctly — plus the encrypted-key, IV, ciphertext, and auth-tag sections of a JWE. Colours are configurable via `editor.semanticTokenColorCustomizations` (defaults set in `configurationDefaults`).

## Commands

| Command | Action |
| --- | --- |
| `Token X-Ray: Inspect token` | Inspect the token at the cursor (or the lens-triggered range) |
| `Token X-Ray: Show rendered claimset` | Open the claimset viewer for the active JWT |
| `Token X-Ray: Show token as decoded JSON` | Open the decoded payload as a regular JSON document |

The two preview commands are also available as title-bar buttons when the editor language is `jwt`.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `tokenXray.jwt.verifySignature` | `false` | Run signature verification in the claimset viewer |
| `tokenXray.jwt.expectedIssuer` | `""` | If set, also assert `iss` equals this value |
| `tokenXray.jwt.expectedAudience` | `""` | If set, also assert `aud` equals this value |
| `tokenXray.jwt.keys` | `[]` | Verification keys — JWK objects, `{ pem, alg, kid? }`, or `{ secret, alg, kid? }` for HMAC |

## Architecture

The codebase is layered so the analysis core stays pure and testable:

```
src/
  analyzers/    # pure detectors — no vscode imports
    jwt/  saml/  x509/  jwk/  oauth/  cookie/  secrets/
  core/         # AnalyzerRegistry + defaultRegistry composition
  providers/    # vscode glue: diagnostics, code lenses, hovers, semantic tokens
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

Sample fixtures live in `/sample` (JWTs, certificates, SAML responses, JWKs, cookie headers, secret-bearing text) and double as the test corpus for the analyzers.

## How can I help?

If you find Token X-Ray useful, a rating on the Visual Studio Marketplace makes a real difference. Bugs and feature requests are very welcome on the GitHub issue tracker, and pull requests even more so.

This is a personal passion project — sponsoring on GitHub helps keep time carved out for it.

---

<sub>Suggested GitHub repository description: **X-ray vision for tokens and secrets in VS Code — locally inspect JWTs, SAML, X.509, JWKs, OAuth tokens, cookies, and detect credentials in any file.**</sub>
