import { Finding } from '../../core/types'
import { JwtAnalyzer } from './analyzer'
import { JwtFindingOptions } from './findings'
import { JwtKind } from './types'
import { verifyJwt, VerifyKeySource } from './verify'

export interface JwtPanelPayload {
  kind: JwtKind
  header: Record<string, unknown>
  claims: Record<string, unknown> | null
  findings: Finding[]
  isEncrypted: boolean
}

export function buildJwtPanelPayload(
  token: string,
  options: JwtFindingOptions = {}
): JwtPanelPayload {
  const analyzer = new JwtAnalyzer(options)
  const [match] = analyzer.detect(token)
  if (!match) {
    throw new Error('Input does not look like a JWT')
  }
  const result = analyzer.analyze(match)
  const headerRows = result.sections.find((s) => s.id === 'header')?.rows ?? []
  const claimRows = result.sections.find((s) => s.id === 'payload')?.rows

  return {
    kind: result.kind as JwtKind,
    header: Object.fromEntries(headerRows.map((r) => [r.key, r.value])),
    claims: claimRows ? Object.fromEntries(claimRows.map((r) => [r.key, r.value])) : null,
    findings: result.findings,
    isEncrypted: result.kind === 'JWE',
  }
}

export async function augmentWithVerification(
  payload: JwtPanelPayload,
  token: string,
  keys: VerifyKeySource[],
  options: { issuer?: string; audience?: string } = {}
): Promise<JwtPanelPayload> {
  if (payload.kind !== 'JWS' || keys.length === 0) return payload
  const result = await verifyJwt(token, { keys, issuer: options.issuer, audience: options.audience })
  const finding: Finding = result.verified
    ? {
        id: 'jwt.signature.verified',
        severity: 'info',
        message: `Signature verified with ${result.alg}${result.matchedKeyKid ? ` (kid: ${result.matchedKeyKid})` : ''}.`,
      }
    : {
        id: 'jwt.signature.invalid',
        severity: 'error',
        message: `Signature verification failed: ${result.error ?? 'unknown error'}.`,
      }
  return { ...payload, findings: [finding, ...payload.findings] }
}

export function findingsBySeverity(findings: Finding[]): {
  errors: Finding[]
  warnings: Finding[]
  infos: Finding[]
} {
  return {
    errors: findings.filter((f) => f.severity === 'error'),
    warnings: findings.filter((f) => f.severity === 'warning'),
    infos: findings.filter((f) => f.severity === 'info'),
  }
}
