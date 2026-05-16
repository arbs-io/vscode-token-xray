import { SecretRule } from '../types'

// Payment-processor credentials: Square access tokens / application secrets /
// application ids, and PayPal long-form access tokens. Each pattern is
// anchored against the surrounding identifier charset with a negative
// lookbehind / lookahead so an identifier such as `xEAAA…` (a variable name)
// cannot accidentally extract a token out of a longer word. The Square body
// alphabets are base64url-ish (`[A-Za-z0-9_-]`); PayPal uses literal `$`
// separators inside the long-form token so the surrounding anchors only need
// to exclude alnum context.

// Square OAuth access tokens carry the literal `EAAA` prefix followed by 60
// or more base64url-ish characters. The negative lookbehind / lookahead
// includes `_-` so the match cannot start or end inside a longer base64url
// body — `EAAA` is the well-known Square production prefix for v2 access
// tokens.
const SQUARE_ACCESS_TOKEN: SecretRule = {
  id: 'secret.square.accessToken',
  vendor: 'square',
  name: 'Square OAuth access token (EAAA…)',
  pattern: /(?<![A-Za-z0-9_-])EAAA[A-Za-z0-9_-]{60,}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Square OAuth access token. Grants Square API access (payments, orders, customers) on behalf of the issuing merchant — revoke immediately if leaked.',
  docUrl: 'https://developer.squareup.com/docs/build-basics/access-tokens',
}

// Square application secrets carry the literal `sq0csp-` prefix followed by
// exactly 43 base64url-ish characters. Confidential to the application —
// required when exchanging OAuth authorisation codes.
const SQUARE_APP_SECRET: SecretRule = {
  id: 'secret.square.appSecret',
  vendor: 'square',
  name: 'Square application secret (sq0csp-…)',
  pattern: /(?<![A-Za-z0-9_-])sq0csp-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,
  severity: 'error',
  description:
    'Square application secret. Confidential OAuth client secret — required only by server-side applications when exchanging authorisation codes.',
  docUrl: 'https://developer.squareup.com/docs/oauth-api/overview',
}

// Square application ids carry the literal `sq0idp-` prefix followed by
// exactly 22 base64url-ish characters. The id is not secret on its own
// (it is shipped in OAuth redirect URLs and SDK initialisation calls) but
// it identifies the application for an attacker, so we surface it at
// `info` severity.
const SQUARE_APP_ID: SecretRule = {
  id: 'secret.square.appId',
  vendor: 'square',
  name: 'Square application id (sq0idp-…)',
  pattern: /(?<![A-Za-z0-9_-])sq0idp-[A-Za-z0-9_-]{22}(?![A-Za-z0-9_-])/g,
  severity: 'info',
  description:
    'Square application id. Not a secret on its own but identifies the Square application for an attacker.',
  docUrl: 'https://developer.squareup.com/docs/oauth-api/overview',
}

// PayPal long-form access tokens are minted by the PayPal OAuth 2.0 service
// and follow the shape `access_token$<env>$<clientId>$<32-hex-suffix>` where
// `<env>` is `production` or `sandbox`. The literal `$` separators must be
// escaped in the JS regex. The negative lookbehind / lookahead anchors
// against the surrounding alnum context so the token cannot be extracted
// from a longer word — the `$` chars themselves are not part of any
// identifier charset, but the leading `access_token` could otherwise be
// claimed from inside a longer identifier such as `xaccess_token…`.
const PAYPAL_ACCESS_TOKEN: SecretRule = {
  id: 'secret.paypal.accessToken',
  vendor: 'paypal',
  name: 'PayPal long-form access token (access_token$…)',
  pattern: /(?<![A-Za-z0-9_])access_token\$(?:production|sandbox)\$[a-z0-9]+\$[a-f0-9]{32}(?![A-Za-z0-9_])/g,
  severity: 'error',
  description:
    'PayPal long-form OAuth 2.0 access token. Authenticates against the PayPal REST APIs (payments, invoicing) on behalf of the issuing merchant — revoke immediately if leaked.',
  docUrl: 'https://developer.paypal.com/api/rest/authentication/',
}

export const PAYMENTS_SECRET_RULES: SecretRule[] = [
  SQUARE_ACCESS_TOKEN,
  SQUARE_APP_SECRET,
  SQUARE_APP_ID,
  PAYPAL_ACCESS_TOKEN,
]
