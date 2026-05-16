# Sample files

These files are for testing the extension end-to-end. Open any of them after pressing F5 (Run Extension) to see the analyzer in action.

The extension auto-detects content — you do **not** need to set the editor language manually. Look for an "Inspect …" CodeLens above each detected token, and check the Problems panel for findings.

## JWT (JSON Web Token)

| File | What it demonstrates |
|------|----------------------|
| `token.jwt`, `token-small.jwt` | Minimal hand-crafted JWS tokens. |
| `secure-api.jwt`, `context.jwt`, `user.jwt`, `uid.jwt` | Generic JWS examples. |
| `azure-ad-access-tokens-v1.jwt`, `azure-ad-access-tokens-v2.jwt` | Azure AD v1/v2 access tokens — exercise the `tid`, `oid`, `appid`, `scp`, `roles` claims. |
| `azure-ad-id-tokens-v1.jwt`, `azure-ad-id-tokens-v2.jwt` | Azure AD ID tokens — exercise OIDC claims (`nonce`, `at_hash`, `c_hash`). |
| `akana.jwt`, `stormpath.jwt` | Vendor-specific JWTs. |

These tokens are intentionally expired in real time; expect the analyzer to flag `jwt.exp.expired` as an error finding.

## SAML 2.0

| File | What it demonstrates |
|------|----------------------|
| `saml-response.xml` | A signed Response containing a signed Assertion with Conditions and an AudienceRestriction. The healthy-path case (besides validity dates being in the past). |
| `saml-response.b64` | The same response, base64-encoded — what an SP receives via the HTTP-POST binding. Open this file and watch the analyzer transparently base64-decode it. |
| `saml-response.redirect` | The same response, DEFLATE-compressed then base64-encoded then URL-encoded — what an IdP sends via the HTTP-Redirect binding (e.g. as the `SAMLRequest` query parameter). |
| `saml-response-unsigned.xml` | An unsigned Response. Exercises the `saml.signature.missing` finding (error severity). |
| `saml-response-encrypted.xml` | A Response containing an EncryptedAssertion. Exercises the `saml.assertion.encrypted` info finding; subject and claims are not displayed because they require the SP's private key to decrypt. |

## X.509 Certificates (PEM)

| File | What it demonstrates |
|------|----------------------|
| `cert-good.pem` | RSA-2048 + SHA-256, valid for 10 years, with Subject Alternative Names — the healthy-path case. Will surface a self-signed info finding since it's not chained to a real CA. |
| `cert-weak-key.pem` | RSA-1024 — exercises `x509.key.weakRsa` (error). Also has no SAN so triggers `x509.san.missing`. |
| `cert-sha1.pem` | RSA-2048 + **SHA-1** signature — exercises `x509.signature.weakAlgorithm` (error). |
| `cert-expired.pem` | Already expired — exercises `x509.validity.expired` (error). |

Certificates are parsed offline using Node's built-in `crypto.X509Certificate` (no external dependency).

## JWK / JWKS

| File | What it demonstrates |
|------|----------------------|
| `jwk-rsa-public.json` | Healthy RSA-2048 public key with `kid`, `alg`, `use`. |
| `jwk-rsa-weak.json` | RSA-1024 — exercises `jwk.rsa.key.weak` (error). |
| `jwk-ec-public.json` | EC P-256 public key with `kid` and `alg`. |
| `jwk-ec-private.json` | EC private key — exercises `jwk.private.present` (error). JWKS endpoints must publish only public keys. |
| `jwks.json` | A JWKS containing the two healthy public keys. |

Parsed purely from JSON; no external dependency.

## Vendor API tokens (GitHub / Slack / Stripe)

| File | What it demonstrates |
|------|----------------------|
| `oauth-tokens.txt` | One fake token per supported pattern. Live-mode credentials (GitHub PATs, Slack tokens, Stripe `sk_live_*` / `rk_live_*`) produce **error** diagnostics. Stripe `*_test_*` keys produce **warning**. Stripe publishable keys (`pk_*`) produce **info** because they're designed for client-side use. |

Each diagnostic carries a vendor-namespaced `code` (e.g. `oauth.github.pat.classic`, `oauth.stripe.secret.live`) so you can filter or suppress per project.

## HTTP cookies (Set-Cookie)

| File | What it demonstrates |
|------|----------------------|
| `cookies.http` | Nine `Set-Cookie` headers covering the security findings: healthy session cookie (no findings), missing `HttpOnly` (warning), missing `Secure` (warning), `SameSite=None` without `Secure` (error), implicit session cookie (info), JWT-as-cookie value (info — points you to the JWT analyzer), cookie deletion via negative `Max-Age` (info), and overly broad `Domain` (warning). |

## Secrets

| File | What it demonstrates |
|------|----------------------|
| `secrets.txt` | A demo PEM RSA private key block and an OpenSSH private key block — both flagged by the generic `secret.privateKey.pem` rule as **error**. Cloud-specific rules (AWS / GCP / Azure / GitHub) will land in follow-up enhancements and add more detections to this file. |

The secret scanner runs on every open document via the generic Diagnostics provider. Diagnostics carry a redacted preview rather than the full key text.

## Trying out signature verification (optional)

For JWT signature verification, set `securityInspector.jwt.verifySignature` to `true` and configure `securityInspector.jwt.keys` with one of:

- `{ "secret": "<shared secret>", "alg": "HS256" }`
- `{ "pem": "-----BEGIN PUBLIC KEY-----\n…", "alg": "RS256", "kid": "your-kid" }`
- A JWK object (`{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "alg": "ES256" }`)

The sample tokens above are mostly unsigned/expired and won't verify against real keys — they're for exercising the **decode + findings** path. To exercise the **verify** path, mint a fresh token with `jose` (or another JWT library) using a key you control, paste it into a new file, then enable verification.
