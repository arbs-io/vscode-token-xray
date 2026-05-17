import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

// HashiCorp Vault service tokens use the `hvs.` prefix followed by 24+
// base64url-ish characters. The negative lookbehind rejects identifiers like
// `my-hvs.token` / `prefix_hvs.foo` that would otherwise be picked up because
// the body uses the same alphabet as common identifier suffixes. No trailing
// anchor because the legitimate token body is variable-length and can run on.
const VAULT_SERVICE_TOKEN: SecretRule = {
  id: 'secret.vault.serviceToken',
  vendor: 'vault',
  name: 'HashiCorp Vault service token (hvs.…)',
  pattern: /(?<![A-Za-z0-9_-])hvs\.[A-Za-z0-9_-]{24,}/g,
  severity: 'error',
  description:
    'HashiCorp Vault service token. Grants Vault API access scoped to the issuing policy — rotate (revoke) immediately if leaked.',
  docUrl: 'https://developer.hashicorp.com/vault/docs/concepts/tokens',
}

// HashiCorp Vault root tokens use the `hvr.` prefix. Root tokens are
// unrestricted and should virtually never appear in source files.
const VAULT_ROOT_TOKEN: SecretRule = {
  id: 'secret.vault.rootToken',
  vendor: 'vault',
  name: 'HashiCorp Vault root token (hvr.…)',
  pattern: /(?<![A-Za-z0-9_-])hvr\.[A-Za-z0-9]{24,}/g,
  severity: 'error',
  description:
    'HashiCorp Vault root token. Unrestricted, never expires by default — revoke immediately if leaked.',
  docUrl: 'https://developer.hashicorp.com/vault/docs/concepts/tokens#root-tokens',
}

const VAULT_LABELLED: SecretRule = {
  id: 'secret.vault.labelled',
  vendor: 'vault',
  name: 'HashiCorp Vault token (env-labelled VAULT_TOKEN=)',
  pattern: /(?:VAULT_TOKEN|vault_token|vaultToken)["']?\s*[:=]\s*["']?[A-Za-z0-9._-]{16,}["']?/g,
  severity: 'error',
  description:
    'HashiCorp Vault token referenced via env var. Anyone with the value can call the Vault API as the issuing identity — revoke immediately if leaked.',
  docUrl: 'https://developer.hashicorp.com/vault/docs/concepts/tokens',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._-]{16,})/),
}

// Terraform Cloud user API tokens follow `<14 alnum>.atlasv1.<60+ base64url>`.
// The 14-char prefix is the user-id segment; `atlasv1` is the literal
// algorithm/version marker; the suffix is the signed body.
const TERRAFORM_CLOUD_USER_TOKEN: SecretRule = {
  id: 'secret.terraformCloud.userToken',
  vendor: 'terraformCloud',
  name: 'Terraform Cloud user API token',
  pattern: /(?<![A-Za-z0-9_-])[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}/g,
  severity: 'error',
  description:
    'Terraform Cloud / Terraform Enterprise user API token. Grants account-level access to the issuing user — revoke immediately if leaked.',
  docUrl: 'https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/api-tokens',
}

const TERRAFORM_CLOUD_LABELLED: SecretRule = {
  id: 'secret.terraformCloud.labelled',
  vendor: 'terraformCloud',
  name: 'Terraform Cloud token (env-labelled TF_TOKEN_app_terraform_io=)',
  pattern: /(?:TF_TOKEN_app_terraform_io|tf_token_app_terraform_io|tfTokenAppTerraformIo)["']?\s*[:=]\s*["']?[A-Za-z0-9._-]{20,}["']?/g,
  severity: 'error',
  description:
    'Terraform Cloud API token referenced via env var. Anyone with the value can run Terraform plans/applies as the issuing user — revoke immediately if leaked.',
  docUrl: 'https://developer.hashicorp.com/terraform/cli/config/config-file#environment-variable-credentials',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9._-]{20,})/),
}

export const VAULT_SECRET_RULES: SecretRule[] = [
  VAULT_SERVICE_TOKEN,
  VAULT_ROOT_TOKEN,
  VAULT_LABELLED,
  TERRAFORM_CLOUD_USER_TOKEN,
  TERRAFORM_CLOUD_LABELLED,
]
