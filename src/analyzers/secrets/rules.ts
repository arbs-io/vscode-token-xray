import { SecretRule } from './types'
import { AI_SECRET_RULES } from './vendorRules/ai'
import { AUTH0_SECRET_RULES } from './vendorRules/auth0'
import { AWS_SECRET_RULES } from './vendorRules/aws'
import { AZURE_SECRET_RULES } from './vendorRules/azure'
import { CLOUDFLARE_SECRET_RULES } from './vendorRules/cloudflare'
import { GCP_SECRET_RULES } from './vendorRules/gcp'
import { GENERIC_SECRET_RULES } from './vendorRules/generic'
import { GITHUB_SECRET_RULES } from './vendorRules/github'
import { OKTA_SECRET_RULES } from './vendorRules/okta'
import { SAILPOINT_SECRET_RULES } from './vendorRules/sailpoint'

const PEM_PRIVATE_KEY: SecretRule = {
  id: 'secret.privateKey.pem',
  vendor: 'generic',
  name: 'PEM private key block',
  pattern: /-----BEGIN ((?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP)?\s?)PRIVATE KEY-----[\s\S]{1,8192}?-----END \1?PRIVATE KEY-----/g,
  severity: 'error',
  description: 'PEM-encoded private key. Should never be committed to source control or sent over insecure channels.',
  docUrl: 'https://datatracker.ietf.org/doc/html/rfc7468',
}

export const BUILT_IN_SECRET_RULES: SecretRule[] = [
  PEM_PRIVATE_KEY,
  ...AWS_SECRET_RULES,
  ...GCP_SECRET_RULES,
  ...OKTA_SECRET_RULES,
  ...CLOUDFLARE_SECRET_RULES,
  ...AUTH0_SECRET_RULES,
  ...SAILPOINT_SECRET_RULES,
  ...AZURE_SECRET_RULES,
  ...GITHUB_SECRET_RULES,
  ...AI_SECRET_RULES,
  ...GENERIC_SECRET_RULES,
]

export function createRuleSet(extraRules: SecretRule[] = []): SecretRule[] {
  const seen = new Set<string>()
  const combined: SecretRule[] = []
  for (const rule of [...BUILT_IN_SECRET_RULES, ...extraRules]) {
    if (seen.has(rule.id)) {
      throw new Error(`Duplicate secret rule id: ${rule.id}`)
    }
    seen.add(rule.id)
    combined.push(rule)
  }
  return combined
}
