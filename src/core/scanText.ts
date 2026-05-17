import { AnalyzerRegistry } from './registry'
import { looksBinary } from './binaryDetection'
import {
  DiagnosticDto,
  DiagnosticsMetrics,
  SuppressionEvent,
  diagnosticsAcrossRegistry,
} from './diagnostics'
import { matchesAnyGlob } from './globMatch'
import { SeverityOverrideMap } from './severityOverrides'

/**
 * Aggregate counters for a single `scanText` call. Sums the registry-
 * boundary `DiagnosticsMetrics` plus the secret-filter drop bucket so
 * the provider can format one line per refresh without re-counting.
 */
export interface ScanTextMetrics extends DiagnosticsMetrics {
  /**
   * Findings dropped because `shouldDropSecrets` returned true (file
   * size cap, `secrets.enabled = false`, or path matched a
   * `secrets.exclude` glob).
   */
  droppedBySecretsFilter: number
  /** Final published diagnostic count (post all filters). */
  published: number
}

export interface SecretsScanSettings {
  /**
   * When false, findings from the `secret` analyzer are dropped. Default: true.
   * Findings from JWT / SAML / X509 / JWK / OAuth / Cookie analyzers are NOT
   * affected by this setting.
   */
  enabled?: boolean
  /**
   * Gitignore-style globs of file paths to skip secret scanning on. When the
   * supplied filename matches one of these globs, `secret`-source findings are
   * dropped. Non-secret findings still flow through. Default: [].
   */
  exclude?: readonly string[]
  /**
   * Skip secret scanning when document length (in characters) exceeds this
   * value. Non-secret findings still flow through. Default: 1 MiB.
   */
  maxFileSizeBytes?: number
}

export interface ScanTextSettings {
  /** Settings affecting the secret analyzer. */
  secrets?: SecretsScanSettings
  /**
   * Per-rule severity override map (forwards directly to
   * `applySeverityOverrides`). Applied at the registry boundary to every
   * analyzer's findings — not just secret findings.
   */
  ruleSeverity?: SeverityOverrideMap
  /**
   * Optional per-suppression sink. Forwarded to
   * `diagnosticsAcrossRegistry.onSuppression`. Fires once for every
   * finding the inline-disable-comment or severity-override pass drops.
   */
  onSuppression?: (event: SuppressionEvent) => void
  /**
   * Optional aggregate-metrics sink. Fires exactly once per scan,
   * after both the registry-boundary filters and the secret-filter
   * step have run. The values are all derived from the pre-existing
   * `all` / `out` arrays inside `scanText` plus the registry-boundary
   * `DiagnosticsMetrics` — no new counters are introduced.
   */
  onMetrics?: (metrics: ScanTextMetrics) => void
  /**
   * Cooperative cancellation. Forwarded to `diagnosticsAcrossRegistry`
   * so a newer scan can pre-empt an in-flight one mid-registry-walk.
   * On abort the function returns `[]` and emits zero metrics; callers
   * that wrap this for vscode diagnostics drop the result via the
   * existing per-URI scan-token guard.
   */
  signal?: AbortSignal
}

export const DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES = 1_048_576 // 1 MiB

/** The analyzer id used by the secret rule registry. Keep in sync with `SecretAnalyzer.id`. */
export const SECRET_SOURCE_ID = 'secret'

/**
 * Pure scan of a document body. Runs the supplied analyzer registry over the
 * text and returns the resulting `DiagnosticDto[]`, with secret-source
 * findings filtered according to `settings.secrets`.
 *
 * The `filename` argument is used for glob matching against
 * `settings.secrets.exclude`. Pass `undefined` for untitled / unsaved buffers
 * — exclude globs will not match.
 *
 * No vscode imports here. The vscode wiring lives in
 * `src/providers/securityDiagnosticsProvider.ts`.
 */
export async function scanText(
  text: string,
  filename: string | undefined,
  registry: AnalyzerRegistry,
  settings: ScanTextSettings = {}
): Promise<DiagnosticDto[]> {
  // Capture the registry-boundary metrics so we can fold them into
  // the per-scan summary we hand back to the caller. We hold a
  // partial object and fill it in after the secret filter step.
  let regMetrics: DiagnosticsMetrics | undefined
  const captureRegMetrics = (m: DiagnosticsMetrics): void => {
    regMetrics = m
  }

  const emitMetrics = (published: number, droppedBySecretsFilter: number): void => {
    if (!settings.onMetrics) return
    const base: DiagnosticsMetrics = regMetrics ?? {
      scanned: 0,
      droppedBySeverityOverride: 0,
      droppedByDisableComments: 0,
    }
    settings.onMetrics({
      ...base,
      droppedBySecretsFilter,
      published,
    })
  }

  if (!text) {
    emitMetrics(0, 0)
    return []
  }
  // Binary buffers (PDFs, images, compiled artefacts that VS Code chose
  // to surface as a TextDocument) produce nothing but high-entropy noise
  // — skip them before paying the regex cost.
  if (looksBinary(text)) {
    emitMetrics(0, 0)
    return []
  }

  const all = await diagnosticsAcrossRegistry(text, registry, {
    ruleSeverity: settings.ruleSeverity,
    onSuppression: settings.onSuppression,
    onMetrics: captureRegMetrics,
    signal: settings.signal,
  })
  if (all.length === 0) {
    emitMetrics(0, 0)
    return all
  }

  if (shouldDropSecrets(text, filename, settings.secrets)) {
    const filtered = all.filter((d) => d.source !== SECRET_SOURCE_ID)
    emitMetrics(filtered.length, all.length - filtered.length)
    return filtered
  }
  emitMetrics(all.length, 0)
  return all
}

/**
 * Returns true when secret-source findings should be dropped for this document.
 * Exposed (and tested) directly so callers can short-circuit work before
 * invoking the full registry if they wish.
 */
export function shouldDropSecrets(
  text: string,
  filename: string | undefined,
  settings: SecretsScanSettings | undefined
): boolean {
  const enabled = settings?.enabled ?? true
  if (!enabled) return true

  const maxBytes = settings?.maxFileSizeBytes ?? DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES
  if (maxBytes >= 0 && text.length > maxBytes) return true

  const exclude = settings?.exclude ?? []
  if (filename && exclude.length > 0 && matchesAnyGlob(filename, exclude)) return true

  return false
}
