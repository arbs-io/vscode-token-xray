import { Severity } from '../../core/types'

export interface TokenPattern {
  id: string
  vendor: string
  kind: string
  pattern: RegExp
  severity: Severity
  description: string
  docUrl?: string
  environment?: 'live' | 'test'
}

export const TOKEN_PATTERNS: TokenPattern[] = [
  {
    id: 'github.pat.classic',
    vendor: 'GitHub',
    kind: 'Classic Personal Access Token',
    pattern: /ghp_[A-Za-z0-9]{36,}/g,
    severity: 'error',
    description: 'GitHub classic PAT — should never be committed to source.',
    docUrl: 'https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
  },
  {
    id: 'github.pat.fineGrained',
    vendor: 'GitHub',
    kind: 'Fine-grained Personal Access Token',
    pattern: /github_pat_[A-Za-z0-9_]{82}/g,
    severity: 'error',
    description: 'GitHub fine-grained PAT — should never be committed to source.',
    docUrl: 'https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
  },
  {
    id: 'github.oauth.userToServer',
    vendor: 'GitHub',
    kind: 'OAuth user-to-server token',
    pattern: /ghu_[A-Za-z0-9]{36,}/g,
    severity: 'error',
    description: 'GitHub OAuth user-to-server access token.',
  },
  {
    id: 'github.oauth.serverToServer',
    vendor: 'GitHub',
    kind: 'OAuth server-to-server token',
    pattern: /ghs_[A-Za-z0-9]{36,}/g,
    severity: 'error',
    description: 'GitHub server-to-server access token (GitHub App installation).',
  },
  {
    id: 'github.oauth.access',
    vendor: 'GitHub',
    kind: 'OAuth access token',
    pattern: /gho_[A-Za-z0-9]{36,}/g,
    severity: 'error',
    description: 'GitHub OAuth user access token.',
  },
  {
    id: 'github.oauth.refresh',
    vendor: 'GitHub',
    kind: 'OAuth refresh token',
    pattern: /ghr_[A-Za-z0-9]{76,}/g,
    severity: 'error',
    description: 'GitHub OAuth refresh token.',
  },

  {
    id: 'slack.bot',
    vendor: 'Slack',
    kind: 'Bot token',
    pattern: /xoxb-\d+-\d+-\d+-[A-Za-z0-9]+/g,
    severity: 'error',
    description: 'Slack bot user OAuth token (xoxb-…).',
    docUrl: 'https://api.slack.com/authentication/token-types',
  },
  {
    id: 'slack.user',
    vendor: 'Slack',
    kind: 'User token',
    pattern: /xoxp-\d+-\d+-\d+-[A-Za-z0-9]+/g,
    severity: 'error',
    description: 'Slack user OAuth token (xoxp-…).',
  },
  {
    id: 'slack.workspace',
    vendor: 'Slack',
    kind: 'Workspace token',
    pattern: /xoxa-(?:2-)?\d+-\d+-\d+-[A-Za-z0-9]+/g,
    severity: 'error',
    description: 'Slack workspace token (xoxa-…).',
  },
  {
    id: 'slack.refresh',
    vendor: 'Slack',
    kind: 'Refresh token',
    pattern: /xoxr-\d+-\d+-\d+-[A-Za-z0-9]+/g,
    severity: 'error',
    description: 'Slack refresh token (xoxr-…).',
  },
  {
    id: 'slack.app',
    vendor: 'Slack',
    kind: 'App-level token',
    pattern: /xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+/g,
    severity: 'error',
    description: 'Slack app-level token (xapp-…).',
  },

  {
    id: 'stripe.secret.live',
    vendor: 'Stripe',
    kind: 'Secret API key (live)',
    pattern: /sk_live_[A-Za-z0-9]{24,}/g,
    severity: 'error',
    description: 'Stripe LIVE secret API key — full account access. Rotate immediately if leaked.',
    docUrl: 'https://stripe.com/docs/keys',
    environment: 'live',
  },
  {
    id: 'stripe.secret.test',
    vendor: 'Stripe',
    kind: 'Secret API key (test)',
    pattern: /sk_test_[A-Za-z0-9]{24,}/g,
    severity: 'warning',
    description: 'Stripe TEST secret API key — only operates against test mode but still should not be committed.',
    environment: 'test',
  },
  {
    id: 'stripe.restricted.live',
    vendor: 'Stripe',
    kind: 'Restricted API key (live)',
    pattern: /rk_live_[A-Za-z0-9]{24,}/g,
    severity: 'error',
    description: 'Stripe LIVE restricted API key — scoped access. Rotate if leaked.',
    environment: 'live',
  },
  {
    id: 'stripe.restricted.test',
    vendor: 'Stripe',
    kind: 'Restricted API key (test)',
    pattern: /rk_test_[A-Za-z0-9]{24,}/g,
    severity: 'warning',
    description: 'Stripe TEST restricted API key.',
    environment: 'test',
  },
  {
    id: 'stripe.publishable.live',
    vendor: 'Stripe',
    kind: 'Publishable key (live)',
    pattern: /pk_live_[A-Za-z0-9]{24,}/g,
    severity: 'info',
    description: 'Stripe LIVE publishable key — designed for client-side use. Not sensitive.',
    environment: 'live',
  },
  {
    id: 'stripe.publishable.test',
    vendor: 'Stripe',
    kind: 'Publishable key (test)',
    pattern: /pk_test_[A-Za-z0-9]{24,}/g,
    severity: 'info',
    description: 'Stripe TEST publishable key — designed for client-side use. Not sensitive.',
    environment: 'test',
  },
]

export interface TokenMatchInfo {
  pattern: TokenPattern
  text: string
  start: number
  end: number
}

export function findTokens(text: string): TokenMatchInfo[] {
  if (!text) return []
  const out: TokenMatchInfo[] = []
  for (const pattern of TOKEN_PATTERNS) {
    pattern.pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.pattern.exec(text)) !== null) {
      out.push({ pattern, text: m[0], start: m.index, end: m.index + m[0].length })
      if (m[0].length === 0) pattern.pattern.lastIndex++
    }
  }
  return out
}
