import {
  Diagnostic,
  DiagnosticSeverity,
  ExtensionContext,
  FileSystemError,
  languages,
  Range,
  TextDocument,
  Uri,
  workspace,
  WorkspaceFolder,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { DiagnosticDto } from '../core/diagnostics'
import { matchIgnore, parseIgnoreFile } from '../core/ignoreFile'
import {
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES,
  ScanTextMetrics,
  ScanTextSettings,
  scanText,
} from '../core/scanText'
import { SeverityOverrideMap } from '../core/severityOverrides'
import { getDebugLogger } from './debugOutputChannel'

const SEVERITY_MAP: Record<DiagnosticDto['severity'], DiagnosticSeverity> = {
  error: DiagnosticSeverity.Error,
  warning: DiagnosticSeverity.Warning,
  information: DiagnosticSeverity.Information,
  hint: DiagnosticSeverity.Hint,
}

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])
const IGNORE_FILE_NAME = '.tokenxrayignore'

function dtoToDiagnostic(dto: DiagnosticDto): Diagnostic {
  const diag = new Diagnostic(
    new Range(dto.range.startLine, dto.range.startColumn, dto.range.endLine, dto.range.endColumn),
    dto.message,
    SEVERITY_MAP[dto.severity]
  )
  diag.source = dto.source
  diag.code = dto.code
  return diag
}

function readScanSettings(uri: Uri): ScanTextSettings {
  const config = workspace.getConfiguration('tokenXray', uri)
  return {
    secrets: {
      enabled: config.get<boolean>('secrets.enabled', true),
      exclude: config.get<string[]>('secrets.exclude', []),
      maxFileSizeBytes: config.get<number>(
        'secrets.maxFileSizeBytes',
        DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES
      ),
    },
    ruleSeverity: config.get<SeverityOverrideMap>('ruleSeverity', {}),
  }
}

function filenameFor(doc: TextDocument): string | undefined {
  if (doc.uri.scheme === 'file') {
    const folder = workspace.getWorkspaceFolder(doc.uri)
    if (folder) {
      const folderPath = folder.uri.fsPath
      const filePath = doc.uri.fsPath
      if (filePath.startsWith(folderPath)) {
        // Strip the workspace prefix + leading separator so exclude globs are
        // matched against a workspace-relative path.
        return filePath.slice(folderPath.length).replace(/^[\\/]+/, '')
      }
    }
    return doc.uri.fsPath
  }
  // untitled buffers — no on-disk filename
  return undefined
}

/**
 * Returns the document's path relative to its workspace folder (forward
 * slashes), or `undefined` when the document isn't on disk or doesn't
 * sit inside any workspace folder. Used by the `.tokenxrayignore` check
 * — un-rooted documents can never match a workspace-scoped ignore file.
 */
function relativeFor(
  doc: TextDocument,
  folder: WorkspaceFolder
): string | undefined {
  if (doc.uri.scheme !== 'file') return undefined
  const folderPath = folder.uri.fsPath
  const filePath = doc.uri.fsPath
  if (!filePath.startsWith(folderPath)) return undefined
  return filePath.slice(folderPath.length).replace(/^[\\/]+/, '').replace(/\\/g, '/')
}

/**
 * Load + parse the `.tokenxrayignore` file at the root of `folder`,
 * returning the active pattern list (or `[]` when no file exists).
 *
 * Any I/O error other than "file not found" is swallowed so the
 * provider keeps working even if the file is unreadable; the cache
 * entry simply falls back to an empty pattern list.
 */
async function loadIgnorePatterns(folder: WorkspaceFolder): Promise<string[]> {
  const uri = Uri.joinPath(folder.uri, IGNORE_FILE_NAME)
  try {
    const bytes = await workspace.fs.readFile(uri)
    const text = new TextDecoder('utf-8').decode(bytes)
    return parseIgnoreFile(text)
  } catch (err) {
    // FileNotFound is the common case (no .tokenxrayignore in the
    // workspace). We treat any read failure as "no patterns" rather
    // than surfacing an error — this is a best-effort feature.
    if (err instanceof FileSystemError) return []
    return []
  }
}

/**
 * Format the per-refresh debug summary line. Spec'd by the
 * `output-channel` enhancement so the channel reads:
 *
 *   `<filename>: scanned N tokens, suppressed K (S secrets / I ignored)`
 *
 * where K = S + I + (severity-override drops). The two override
 * buckets are summed into "ignored" because the user-facing
 * distinction the spec asks for is "secrets-filter drop" (path /
 * size / disabled) vs. "everything else" (inline directives +
 * severity overrides), both of which the user controls but in
 * different ways.
 */
function formatScanSummary(label: string, metrics: ScanTextMetrics): string {
  const ignored = metrics.droppedByDisableComments + metrics.droppedBySeverityOverride
  const suppressed = metrics.droppedBySecretsFilter + ignored
  return `${label}: scanned ${metrics.scanned} tokens, suppressed ${suppressed} (${metrics.droppedBySecretsFilter} secrets / ${ignored} ignored)`
}

export function registerSecurityDiagnosticsProvider(context: ExtensionContext) {
  const registry = createDefaultRegistry()
  const collection = languages.createDiagnosticCollection('tokenXray')
  context.subscriptions.push(collection)
  const debugLog = getDebugLogger(context)

  // Per-workspace-folder pattern cache. Refreshed on startup and any
  // time files in the workspace change so adding / editing / deleting
  // a `.tokenxrayignore` takes effect without an extension reload.
  const ignoreCache = new Map<string, string[]>()

  const refreshIgnoreCache = async () => {
    const folders = workspace.workspaceFolders ?? []
    ignoreCache.clear()
    for (const folder of folders) {
      const patterns = await loadIgnorePatterns(folder)
      ignoreCache.set(folder.uri.toString(), patterns)
    }
  }

  /** True when any workspace folder's `.tokenxrayignore` excludes this doc. */
  const isIgnored = (doc: TextDocument): boolean => {
    if (doc.uri.scheme !== 'file') return false
    const folder = workspace.getWorkspaceFolder(doc.uri)
    if (!folder) return false
    const patterns = ignoreCache.get(folder.uri.toString())
    if (!patterns || patterns.length === 0) return false
    const rel = relativeFor(doc, folder)
    if (!rel) return false
    return matchIgnore(rel, patterns)
  }

  const refresh = async (doc: TextDocument) => {
    if (!SUPPORTED_SCHEMES.has(doc.uri.scheme)) {
      collection.delete(doc.uri)
      return
    }
    if (isIgnored(doc)) {
      collection.delete(doc.uri)
      return
    }
    try {
      const settings = readScanSettings(doc.uri)
      const filename = filenameFor(doc)
      // Pretty label for the debug summary: prefer the workspace-
      // relative path computed by `filenameFor`, fall back to the
      // URI's last path segment for untitled buffers / files that
      // aren't inside a workspace folder.
      const debugLabel =
        filename ?? doc.uri.path.split('/').pop() ?? doc.uri.toString()
      const settingsWithDebug: ScanTextSettings = {
        ...settings,
        onSuppression: (event) => {
          debugLog(
            `${debugLabel}: suppressed ${event.findingId} (${event.analyzerId}) at line ${event.startLine + 1} via ${event.reason}`
          )
        },
        onMetrics: (metrics) => {
          debugLog(formatScanSummary(debugLabel, metrics))
        },
      }
      const dtos = await scanText(doc.getText(), filename, registry, settingsWithDebug)
      collection.set(doc.uri, dtos.map(dtoToDiagnostic))
    } catch {
      collection.delete(doc.uri)
    }
  }

  const refreshAll = () => {
    for (const doc of workspace.textDocuments) {
      void refresh(doc)
    }
  }

  // Initial population: load ignore patterns, then scan every open
  // document. Documents opened before the cache is ready are still
  // covered because `refresh` only consults the cache at scan time.
  void (async () => {
    await refreshIgnoreCache()
    refreshAll()
  })()

  /**
   * `.tokenxrayignore` may be created, deleted, or change content at
   * runtime. Each event invalidates the cache and re-scans every open
   * document so suppression takes effect immediately. We don't try to
   * narrow down which folder changed — `.tokenxrayignore` is small and
   * the cache rebuild is cheap.
   */
  const refreshOnIgnoreEvent = async () => {
    await refreshIgnoreCache()
    refreshAll()
  }

  context.subscriptions.push(
    workspace.onDidOpenTextDocument((doc) => void refresh(doc)),
    workspace.onDidChangeTextDocument((e) => void refresh(e.document)),
    workspace.onDidCloseTextDocument((doc) => collection.delete(doc.uri)),
    workspace.onDidChangeConfiguration((e) => {
      if (
        !e.affectsConfiguration('tokenXray.secrets') &&
        !e.affectsConfiguration('tokenXray.ruleSeverity')
      ) {
        return
      }
      refreshAll()
    }),
    workspace.onDidCreateFiles(() => void refreshOnIgnoreEvent()),
    workspace.onDidDeleteFiles(() => void refreshOnIgnoreEvent()),
    workspace.onDidChangeWorkspaceFolders(() => void refreshOnIgnoreEvent()),
    // Saving an edited `.tokenxrayignore` fires onDidSaveTextDocument,
    // not onDidCreateFiles, so we hook that path too.
    workspace.onDidSaveTextDocument((doc) => {
      const base = doc.uri.path.split('/').pop()
      if (base === IGNORE_FILE_NAME) void refreshOnIgnoreEvent()
    })
  )
}
