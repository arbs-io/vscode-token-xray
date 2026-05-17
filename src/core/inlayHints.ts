import { AnalysisResult, Finding, Section, SectionRow } from './types'

/**
 * Range describing where a token was detected, in zero-based line/column
 * coordinates. Mirrors the shape produced by `scanDocument` so the
 * provider adapter can pass `DetectedToken` instances through unchanged.
 */
export interface HitRange {
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
}

/**
 * Plain-data inlay hint emitted by the pure mapper. The vscode-aware
 * provider adapter converts this into an actual `vscode.InlayHint`.
 *
 * `position` is the location the hint should render at — we anchor every
 * hint to the **end** of the detected token so the inline annotation
 * trails the token text, matching the convention used by mainstream
 * inlay-hint providers.
 */
export interface InlayHintDto {
  position: { line: number; column: number }
  label: string
  tooltip?: string
}

export interface InlayHintOptions {
  /**
   * Override "now" for deterministic testing of the relative-date
   * heuristics (e.g. `[exp in 3d]` / `[exp tomorrow]`). Defaults to
   * `Date.now()` when omitted.
   */
  now?: number
}

const MS_PER_DAY = 24 * 60 * 60 * 1000

/**
 * Pure mapper from analyzer output to a list of inline annotation DTOs.
 *
 * Per the backlog spec, the function emits at most a handful of hints
 * per token, with heuristics tuned to call out the things a security
 * reviewer cares about at a glance:
 *
 *   - JWT / PASETO  → `[expired]` / `[exp tomorrow]` / `[exp in 3d]` /
 *                     `[exp today]`. Falls back to the first ISO-looking
 *                     timestamp we can find in the `payload` section
 *                     (so PASETO claims map through naturally).
 *   - x509          → `[expired]` when the validity finding fires,
 *                     `[RSA-1024]` (or whatever bits we recover from the
 *                     `keyDetails` row) when the weak-RSA finding fires.
 *   - samlMetadata  → `[expired]` when at least one signing cert is
 *                     expired.
 *   - oauth         → `[live]` when a finding is severity error AND the
 *                     `environment` row reports `live`.
 *   - secret        → `[secret]` for every error-severity finding.
 *
 * Anything else returns an empty array — we never invent annotations for
 * informational findings that would only add noise.
 *
 * The function never throws and never reads from anything but the
 * provided result + range; this lets the unit tests assert behaviour
 * with a hand-crafted `AnalysisResult` and no fixtures.
 */
type Position = { line: number; column: number }
type HintBuilder = (result: AnalysisResult, position: Position, now: number) => InlayHintDto[]

const HINT_BUILDERS: Record<string, HintBuilder> = {
  jwt: (result, position, now) => collect(buildExpHint(result, position, now)),
  paseto: (result, position, now) => collect(buildExpHint(result, position, now)),
  x509: (result, position) =>
    collect(buildX509ValidityHint(result, position), buildX509KeyHint(result, position)),
  samlMetadata: (result, position) =>
    collect(buildSamlMetadataValidityHint(result, position), buildSamlMetadataKeyHint(result, position)),
  oauth: (result, position) => collect(buildOauthLiveHint(result, position)),
  secret: (result, position) => collect(buildSecretHint(result, position)),
}

function collect(...hints: Array<InlayHintDto | undefined>): InlayHintDto[] {
  return hints.filter((h): h is InlayHintDto => Boolean(h))
}

export function findingsToInlayDtos(
  result: AnalysisResult,
  hitRange: HitRange,
  options: InlayHintOptions = {}
): InlayHintDto[] {
  if (!result || !hitRange) return []
  const builder = HINT_BUILDERS[result.analyzerId]
  if (!builder) return []
  const position: Position = { line: hitRange.endLine, column: hitRange.endColumn }
  return builder(result, position, options.now ?? Date.now())
}

function buildExpHint(
  result: AnalysisResult,
  position: { line: number; column: number },
  now: number
): InlayHintDto | undefined {
  const expired = result.findings.some(
    (f) => f.id === 'jwt.exp.expired' || f.id === 'paseto.exp.expired'
  )
  if (expired) {
    return { position, label: '[expired]', tooltip: 'Token expiration time has already elapsed.' }
  }

  const expSection = findSectionByIds(result, ['payload', 'claims'])
  if (!expSection) return undefined
  const expRow = findRowByKey(expSection, 'exp')
  if (!expRow) return undefined

  const expMs = parseTimestampValue(expRow.value)
  if (expMs === undefined) return undefined

  if (expMs <= now) {
    return { position, label: '[expired]', tooltip: 'Token expiration time has already elapsed.' }
  }

  const remainingMs = expMs - now
  const remainingDays = Math.floor(remainingMs / MS_PER_DAY)

  let label: string
  if (remainingDays === 0) {
    label = '[exp today]'
  } else if (remainingDays === 1) {
    label = '[exp tomorrow]'
  } else {
    label = `[exp in ${remainingDays}d]`
  }

  return {
    position,
    label,
    tooltip: `Token expires at ${new Date(expMs).toISOString()}.`,
  }
}

function buildX509ValidityHint(
  result: AnalysisResult,
  position: { line: number; column: number }
): InlayHintDto | undefined {
  const expired = result.findings.some((f) => f.id === 'x509.validity.expired')
  if (!expired) return undefined
  return {
    position,
    label: '[expired]',
    tooltip: 'Certificate notAfter is in the past.',
  }
}

function buildX509KeyHint(
  result: AnalysisResult,
  position: { line: number; column: number }
): InlayHintDto | undefined {
  const weakRsa = result.findings.find((f) => f.id === 'x509.key.weakRsa')
  if (!weakRsa) return undefined
  const bits = extractRsaBits(result, weakRsa)
  if (bits === undefined) return undefined
  return {
    position,
    label: `[RSA-${bits}]`,
    tooltip: `RSA key is ${bits} bits — below the recommended 2048-bit minimum.`,
  }
}

function buildSamlMetadataValidityHint(
  result: AnalysisResult,
  position: { line: number; column: number }
): InlayHintDto | undefined {
  const expired = result.findings.some((f) => f.id === 'samlMeta.cert.expired')
  if (!expired) return undefined
  return {
    position,
    label: '[expired]',
    tooltip: 'At least one SAML metadata signing certificate has expired.',
  }
}

function buildSamlMetadataKeyHint(
  result: AnalysisResult,
  position: { line: number; column: number }
): InlayHintDto | undefined {
  const weakRsa = result.findings.find((f) => f.id === 'samlMeta.cert.weakRsa')
  if (!weakRsa) return undefined
  const bits = extractRsaBits(result, weakRsa)
  if (bits === undefined) return undefined
  return {
    position,
    label: `[RSA-${bits}]`,
    tooltip: `Signing certificate uses an RSA key of ${bits} bits.`,
  }
}

function buildOauthLiveHint(
  result: AnalysisResult,
  position: { line: number; column: number }
): InlayHintDto | undefined {
  const hasErrorFinding = result.findings.some((f) => f.severity === 'error')
  if (!hasErrorFinding) return undefined
  const tokenSection = findSectionByIds(result, ['token'])
  if (!tokenSection) return undefined
  const envRow = findRowByKey(tokenSection, 'environment')
  if (!envRow) return undefined
  if (String(envRow.value).toLowerCase() !== 'live') return undefined
  return {
    position,
    label: '[live]',
    tooltip: 'Token operates against the LIVE / production environment.',
  }
}

function buildSecretHint(
  result: AnalysisResult,
  position: { line: number; column: number }
): InlayHintDto | undefined {
  const errorFinding = result.findings.find((f) => f.severity === 'error')
  if (!errorFinding) return undefined
  return {
    position,
    label: '[secret]',
    tooltip: errorFinding.message,
  }
}

function findSectionByIds(result: AnalysisResult, ids: string[]): Section | undefined {
  return result.sections.find((section) => ids.includes(section.id))
}

function findRowByKey(section: Section, key: string): SectionRow | undefined {
  return section.rows.find((row) => row.key === key)
}

/**
 * Recover a millisecond-since-epoch value from whatever shape a
 * timestamp claim takes in `AnalysisResult.sections`.
 *
 * The JWT analyzer formats numeric `exp` as `${seconds} (${ISO})`. The
 * PASETO analyzer passes the raw claim through, which can be a string
 * ISO timestamp or a number. We accept all three.
 */
function secondsOrMillis(value: number): number {
  // Heuristic: small numbers are seconds, large numbers are milliseconds.
  // Anything below year 5000 in seconds (≈ 95 billion) is treated as seconds.
  return value < 1e12 ? value * 1000 : value
}

function parseTimestampString(value: string): number | undefined {
  const isoMatch = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/.exec(value)
  if (isoMatch) {
    const ms = Date.parse(isoMatch[0])
    if (Number.isFinite(ms)) return ms
  }
  const parsed = Date.parse(value)
  if (Number.isFinite(parsed)) return parsed
  const asNumber = Number(value)
  if (Number.isFinite(asNumber) && asNumber > 0) return secondsOrMillis(asNumber)
  return undefined
}

function parseTimestampValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return secondsOrMillis(value)
  if (typeof value === 'string') return parseTimestampString(value)
  return undefined
}

/**
 * Extract the RSA bit count for a weak-key hint. Prefers the
 * `keyDetails` row (e.g. `RSA-1024`) and falls back to parsing the
 * finding message (which the X.509 analyzer formats as
 * `RSA key is ${bits} bits …`).
 */
function extractRsaBits(result: AnalysisResult, finding: Finding): number | undefined {
  for (const section of result.sections) {
    for (const row of section.rows) {
      if (row.key === 'keyDetails' && typeof row.value === 'string') {
        const m = /RSA[-\s](\d+)/i.exec(row.value)
        if (m) return Number(m[1])
      }
    }
  }
  const m = /(\d+)\s*bits/i.exec(finding.message)
  if (m) return Number(m[1])
  return undefined
}
