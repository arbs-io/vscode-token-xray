import { Finding } from '../../core/types'
import { Sigv4Components } from './parser'

const SIGV4_DOC_URL =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html'

/**
 * Map parsed AWS SigV4 components to the set of findings the UI surfaces.
 *
 * Emitted ids:
 *   - `awsSigv4.accessKeyExposed`         (warning) — always, since the access
 *     key id is plaintext inside the Credential field of a SigV4 header.
 *   - `awsSigv4.session.token`            (info)    — when the access key id
 *     starts with `ASIA`, indicating a temporary STS session credential.
 *   - `awsSigv4.signedHeaders.missingHost` (warning) — when `host` is not in
 *     the SignedHeaders list. The canonical request normally requires `host`
 *     to be signed; missing it is a strong indicator of a malformed signature
 *     or a non-canonical client.
 */
export function findingsForSigv4(components: Sigv4Components): Finding[] {
  const findings: Finding[] = []

  findings.push({
    id: 'awsSigv4.accessKeyExposed',
    severity: 'warning',
    message: `AWS access key id "${components.accessKeyId}" exposed in plaintext via SigV4 Authorization header (region "${components.region}", service "${components.service}"). Treat as a credential leak and rotate.`,
    docUrl: SIGV4_DOC_URL,
  })

  if (components.accessKeyId.startsWith('ASIA')) {
    findings.push({
      id: 'awsSigv4.session.token',
      severity: 'info',
      message: `Access key id "${components.accessKeyId}" begins with ASIA — this is an STS temporary session credential. It will expire automatically but should not be committed.`,
      docUrl: 'https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html',
    })
  }

  if (!components.signedHeaders.includes('host')) {
    findings.push({
      id: 'awsSigv4.signedHeaders.missingHost',
      severity: 'warning',
      message: `SigV4 SignedHeaders list does not include "host" — the AWS canonical request normally requires "host" to be signed. Verify the signing implementation.`,
      docUrl: SIGV4_DOC_URL,
    })
  }

  return findings
}
