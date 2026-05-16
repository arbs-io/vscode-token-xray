import { SecretRule } from '../types'

const sensitiveAfterDelimiter = (raw: string, valueRe: RegExp) => {
  const m = valueRe.exec(raw)
  if (!m) return { start: 0, end: raw.length }
  const start = raw.lastIndexOf(m[1])
  return { start, end: start + m[1].length }
}

const STORAGE_ACCOUNT_KEY: SecretRule = {
  id: 'secret.azure.accountKey',
  vendor: 'azure',
  name: 'Azure storage / Cosmos AccountKey',
  pattern: /AccountKey\s*=\s*[A-Za-z0-9+/=]{60,}/g,
  severity: 'error',
  description:
    'Azure storage or Cosmos DB AccountKey embedded in a connection string. Grants full data-plane access to the account.',
  docUrl: 'https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /=\s*([A-Za-z0-9+/=]{60,})/),
}

const SHARED_ACCESS_KEY: SecretRule = {
  id: 'secret.azure.sharedAccessKey',
  vendor: 'azure',
  name: 'Azure SharedAccessKey (Service Bus / Event Hubs / IoT Hub)',
  pattern: /SharedAccessKey\s*=\s*[A-Za-z0-9+/=]{40,}/g,
  severity: 'error',
  description:
    'Azure SAS signing key for Service Bus, Event Hubs, or IoT Hub. Anyone with this key can mint SAS tokens.',
  docUrl: 'https://learn.microsoft.com/azure/service-bus-messaging/service-bus-sas',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /=\s*([A-Za-z0-9+/=]{40,})/),
}

const SAS_TOKEN: SecretRule = {
  id: 'secret.azure.sasToken',
  vendor: 'azure',
  name: 'Azure SAS token (query string)',
  pattern: /\bsv=\d{4}-\d{2}-\d{2}(?:&[A-Za-z0-9_-]+=[^&\s"<>]*){1,}&sig=[A-Za-z0-9%/+]+(?:&[A-Za-z0-9_-]+=[^&\s"<>]*)*/g,
  severity: 'error',
  description:
    'Azure Shared Access Signature token (signed URL fragment). Whoever holds it has the granted permissions until "se" expiry.',
  docUrl: 'https://learn.microsoft.com/azure/storage/common/storage-sas-overview',
}

const CLIENT_SECRET: SecretRule = {
  id: 'secret.azure.clientSecret',
  vendor: 'azure',
  name: 'Azure AD application client secret (labelled)',
  pattern: /(?:AZURE_CLIENT_SECRET|AAD_CLIENT_SECRET|ARM_CLIENT_SECRET|azure_client_secret|azureClientSecret)["']?\s*[:=]\s*["']?[A-Za-z0-9~._-]{32,}["']?/g,
  severity: 'error',
  description:
    'Azure / Entra ID app registration client secret. Grants the app identity full delegated/application permissions for its API scopes.',
  docUrl: 'https://learn.microsoft.com/entra/identity-platform/quickstart-register-app',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([A-Za-z0-9~._-]{32,})/),
}

const SUBSCRIPTION_ID: SecretRule = {
  id: 'secret.azure.subscriptionId',
  vendor: 'azure',
  name: 'Azure subscription ID (labelled)',
  pattern: /(?:AZURE_SUBSCRIPTION_ID|ARM_SUBSCRIPTION_ID|azure_subscription_id|azureSubscriptionId)["']?\s*[:=]\s*["']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']?/g,
  severity: 'info',
  description: 'Azure subscription identifier. Not a secret on its own but identifies your account to an attacker.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([0-9a-fA-F-]{36})/),
}

const TENANT_ID: SecretRule = {
  id: 'secret.azure.tenantId',
  vendor: 'azure',
  name: 'Azure / Entra tenant ID (labelled)',
  pattern: /(?:AZURE_TENANT_ID|AAD_TENANT_ID|ARM_TENANT_ID|azure_tenant_id|azureTenantId)["']?\s*[:=]\s*["']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']?/g,
  severity: 'info',
  description: 'Entra ID tenant identifier. Identifier only — not a secret but identifies your directory.',
  sensitiveSpan: (raw) => sensitiveAfterDelimiter(raw, /[:=]\s*["']?([0-9a-fA-F-]{36})/),
}

export const AZURE_SECRET_RULES: SecretRule[] = [
  STORAGE_ACCOUNT_KEY,
  SHARED_ACCESS_KEY,
  SAS_TOKEN,
  CLIENT_SECRET,
  SUBSCRIPTION_ID,
  TENANT_ID,
]
