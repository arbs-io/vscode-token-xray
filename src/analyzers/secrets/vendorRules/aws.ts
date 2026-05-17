import { SecretRule } from '../types'

const EXAMPLE_ACCOUNT_IDS = new Set(['123456789012', '111122223333', '444455556666'])

const ACCESS_KEY_ID: SecretRule = {
  id: 'secret.aws.accessKeyId',
  vendor: 'aws',
  name: 'AWS access key ID',
  pattern: /\bAKIA[0-9A-Z]{16}\b/g,
  severity: 'error',
  description: 'AWS long-term IAM access key ID. Rotate the associated key pair immediately if leaked.',
  docUrl: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
}

const SESSION_ACCESS_KEY_ID: SecretRule = {
  id: 'secret.aws.sessionAccessKeyId',
  vendor: 'aws',
  name: 'AWS STS temporary access key ID',
  pattern: /\bASIA[0-9A-Z]{16}\b/g,
  severity: 'warning',
  description: 'AWS STS temporary access key ID. Expires automatically but should not be committed.',
}

const SECRET_ACCESS_KEY: SecretRule = {
  id: 'secret.aws.secretAccessKey',
  vendor: 'aws',
  name: 'AWS secret access key',
  pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey)["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/g,
  severity: 'error',
  description: 'AWS secret access key adjacent to a key-name label. Rotate immediately if leaked.',
  sensitiveSpan: (raw) => {
    const m = /[:=]\s*["']?([A-Za-z0-9/+=]{40})/.exec(raw)
    if (!m) return { start: 0, end: raw.length }
    const valueStart = m.index + m[0].length - m[1].length
    return { start: valueStart, end: valueStart + m[1].length }
  },
}

const ARN: SecretRule = {
  id: 'secret.aws.arn',
  vendor: 'aws',
  name: 'AWS ARN with account ID',
  pattern: /\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:[^\s"'<>]+/g,
  severity: 'info',
  description: 'AWS Resource Name. The 12-digit account ID is embedded and considered semi-sensitive.',
  validate: (raw) => {
    const m = /:(\d{12}):/.exec(raw)
    return !!m && !EXAMPLE_ACCOUNT_IDS.has(m[1])
  },
}

export const AWS_SECRET_RULES: SecretRule[] = [
  ACCESS_KEY_ID,
  SESSION_ACCESS_KEY_ID,
  SECRET_ACCESS_KEY,
  ARN,
]
