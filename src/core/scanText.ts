import { AnalyzerRegistry } from './registry'
import { DiagnosticDto, diagnosticsAcrossRegistry } from './diagnostics'
import { matchesAnyGlob } from './globMatch'

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
  if (!text) return []

  const all = await diagnosticsAcrossRegistry(text, registry)
  if (all.length === 0) return all

  if (shouldDropSecrets(text, filename, settings.secrets)) {
    return all.filter((d) => d.source !== SECRET_SOURCE_ID)
  }
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
