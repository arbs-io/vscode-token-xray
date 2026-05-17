import { SecretRule } from '../types'

// Note: token-form GitHub credentials (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)
// are already detected by the OAuth-token-analyzer's vendor patterns
// (`oauth.github.*`). This rule set focuses on the *additional* GitHub
// surfaces that the OAuth analyzer does not classify — labelled env-var
// secrets — so there is no duplicate diagnostic on the same range.

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

const APP_CLIENT_SECRET: SecretRule = {
  id: 'secret.github.appClientSecret',
  vendor: 'github',
  name: 'GitHub App / OAuth App client_secret (labelled)',
  pattern: /(?:GITHUB_CLIENT_SECRET|GH_CLIENT_SECRET|GITHUB_APP_CLIENT_SECRET|github_client_secret|githubClientSecret|githubAppClientSecret)["']?\s*[:=]\s*["']?[A-Fa-f0-9]{40}["']?/g,
  severity: 'error',
  description:
    'GitHub App or OAuth App client_secret (40 hex chars). Server-side credential — rotate immediately if leaked.',
  docUrl: 'https://docs.github.com/apps/creating-github-apps',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Fa-f0-9]{40})/),
}

const WEBHOOK_SECRET: SecretRule = {
  id: 'secret.github.webhookSecret',
  vendor: 'github',
  name: 'GitHub webhook secret (labelled)',
  pattern: /(?:GITHUB_WEBHOOK_SECRET|GH_WEBHOOK_SECRET|github_webhook_secret|githubWebhookSecret)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{16,}["']?/g,
  severity: 'error',
  description:
    'GitHub webhook signing secret. Anyone with it can forge `X-Hub-Signature-256` headers that pass verification.',
  docUrl: 'https://docs.github.com/webhooks/using-webhooks/validating-webhook-deliveries',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9_-]{16,})/),
}

const APP_PRIVATE_KEY_PATH: SecretRule = {
  id: 'secret.github.appPrivateKeyPath',
  vendor: 'github',
  name: 'GitHub App private key file path (labelled)',
  pattern: /(?:GITHUB_APP_PRIVATE_KEY_PATH|GH_APP_PRIVATE_KEY_PATH|github_app_private_key_path|githubAppPrivateKeyPath)["']?\s*[:=]\s*["']?(?:[A-Za-z]:)?[\/\\][^\s"']{1,256}\.pem["']?/g,
  severity: 'info',
  description:
    'Path to a GitHub App private key .pem file. The file itself should be excluded from source control; surfacing the path here flags the location to review.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?((?:[A-Za-z]:)?[\/\\][^\s"']{1,256}\.pem)/),
}

export const GITHUB_SECRET_RULES: SecretRule[] = [
  APP_CLIENT_SECRET,
  WEBHOOK_SECRET,
  APP_PRIVATE_KEY_PATH,
]
