import {
  Diagnostic,
  DiagnosticSeverity,
  ExtensionContext,
  FileSystemError,
  languages,
  Range,
  TextDocument,
  Uri,
  window,
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
import { effectiveTabUri, openTabUriStrings } from '../utils/openTabs'
import { getDebugLogger } from './debugOutputChannel'

const SEVERITY_MAP: Record<DiagnosticDto['severity'], DiagnosticSeverity> = {
  error: DiagnosticSeverity.Error,
  warning: DiagnosticSeverity.Warning,
  information: DiagnosticSeverity.Information,
  hint: DiagnosticSeverity.Hint,
}

// `vscode-notebook-cell` is opted in so each Jupyter notebook cell flows
// through the diagnostics pipeline like an ordinary source document. VS Code
// surfaces every cell as its own `TextDocument` and fires the standard
// open/change/close events for it, so no separate notebook listener is needed.
const SUPPORTED_SCHEMES = new Set(['file', 'untitled', 'vscode-notebook-cell'])
const IGNORE_FILE_NAME = '.tokenxrayignore'
const GITIGNORE_FILE_NAME = '.gitignore'

/**
 * Recover the parent `.ipynb` file path from a `vscode-notebook-cell` URI.
 *
 * VS Code encodes the cell URI as `vscode-notebook-cell:///path/to/file.ipynb#cellId`,
 * so the notebook's on-disk path lives in `uri.path` and the cell id lives in
 * `uri.fragment`. Building a synthetic `file:` URI with the same `.path` lets
 * the caller reuse the existing `filenameFor` / `relativeFor` plumbing — the
 * fsPath conversion handles the leading slash + Windows drive-letter quirks
 * exactly the same way it does for a real file URI.
 */
function notebookFileUri(cellUri: Uri): Uri | undefined {
  if (cellUri.scheme !== 'vscode-notebook-cell') return undefined
  if (!cellUri.path) return undefined
  return cellUri.with({ scheme: 'file', fragment: '' })
}

function dtoToDiagnostic(dto: DiagnosticDto): Diagnostic {
  const diag = new Diagnostic(
    new Range(dto.range.startLine, dto.range.startColumn, dto.range.endLine, dto.range.endColumn),
    dto.message,
    SEVERITY_MAP[dto.severity]
  )
  // The diagnostic source is the user-visible label in the Problems panel
  // AND the filter used by the findings tree view and status bar badge,
  // so we pin it to the constant 'tokenXray'. The originating analyzer id
  // remains recoverable via the first dot-segment of `code` (e.g. `jwt.*`).
  diag.source = 'tokenXray'
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
  // For notebook cell documents the on-disk filename is the parent
  // `.ipynb`; the cell URI itself has no on-disk representation. Falling
  // back to the synthesised file URI keeps exclude-glob matching aligned
  // with how the user thinks about the file (`notebooks/leak.ipynb`).
  const sourceUri = notebookFileUri(doc.uri) ?? doc.uri
  if (sourceUri.scheme === 'file') {
    const folder = workspace.getWorkspaceFolder(sourceUri)
    if (folder) {
      const folderPath = folder.uri.fsPath
      const filePath = sourceUri.fsPath
      if (filePath.startsWith(folderPath)) {
        // Strip the workspace prefix + leading separator so exclude globs are
        // matched against a workspace-relative path.
        return filePath.slice(folderPath.length).replace(/^[\\/]+/, '')
      }
    }
    return sourceUri.fsPath
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
  // For notebook cell documents the path is on the parent `.ipynb` URI;
  // applying the ignore pattern against that path means ignoring
  // `*.ipynb` suppresses every cell in the notebook in one shot.
  const sourceUri = notebookFileUri(doc.uri) ?? doc.uri
  if (sourceUri.scheme !== 'file') return undefined
  const folderPath = folder.uri.fsPath
  const filePath = sourceUri.fsPath
  if (!filePath.startsWith(folderPath)) return undefined
  return filePath.slice(folderPath.length).replace(/^[\\/]+/, '').replace(/\\/g, '/')
}

/**
 * Read a single ignore file at the root of `folder` and return its
 * parsed pattern list. Missing or unreadable files yield `[]` so the
 * caller can merge multiple sources without per-file error handling.
 */
async function loadPatternsFromFile(
  folder: WorkspaceFolder,
  fileName: string
): Promise<string[]> {
  const uri = Uri.joinPath(folder.uri, fileName)
  try {
    const bytes = await workspace.fs.readFile(uri)
    const text = new TextDecoder('utf-8').decode(bytes)
    return parseIgnoreFile(text)
  } catch (err) {
    if (err instanceof FileSystemError) return []
    return []
  }
}

/**
 * Active ignore-pattern set for a workspace folder. Always includes
 * `.tokenxrayignore`; also folds in workspace-root `.gitignore` when
 * `tokenXray.respectGitignore` is true (the default). Most projects
 * already gitignore `.env*`, `secrets/`, `*.pem`, etc. — honouring
 * those by default avoids noisy diagnostics on files the user has
 * already declared off-limits.
 *
 * We deliberately read only the root `.gitignore`; nested .gitignores
 * would require walking the file tree and re-resolving every scan.
 */
async function loadIgnorePatterns(folder: WorkspaceFolder): Promise<string[]> {
  const tokenXrayPatterns = await loadPatternsFromFile(folder, IGNORE_FILE_NAME)
  const config = workspace.getConfiguration('tokenXray', folder.uri)
  const respectGitignore = config.get<boolean>('respectGitignore', true)
  if (!respectGitignore) return tokenXrayPatterns
  const gitignorePatterns = await loadPatternsFromFile(folder, GITIGNORE_FILE_NAME)
  // .gitignore patterns come first so a later `.tokenxrayignore` entry
  // (including `!negations`) can override them — matches gitignore's
  // "last matching rule wins" semantics.
  return [...gitignorePatterns, ...tokenXrayPatterns]
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

/**
 * Trailing-edge debounce window for `onDidChangeTextDocument` events.
 * Tuned so a typing burst (one keystroke per ~70ms) resolves to a single
 * trailing scan once the user pauses. Open/close events bypass this and
 * still scan immediately so the Problems panel populates without lag.
 */
const CHANGE_DEBOUNCE_MS = 250

export interface DiagnosticsProviderOptions {
  /** Overrides {@link CHANGE_DEBOUNCE_MS}. Set to 0 in tests for sync behaviour. */
  changeDebounceMs?: number
}

export function registerSecurityDiagnosticsProvider(
  context: ExtensionContext,
  options: DiagnosticsProviderOptions = {}
) {
  const registry = createDefaultRegistry()
  const collection = languages.createDiagnosticCollection('tokenXray')
  context.subscriptions.push(collection)
  const debugLog = getDebugLogger(context)
  const changeDebounceMs = options.changeDebounceMs ?? CHANGE_DEBOUNCE_MS

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

  // Per-URI scan-generation map. `claimScan` issues a globally-unique
  // token; `isLatestScan` answers whether that token is still the most
  // recent one for the URI; `invalidateScan` drops the URI's slot so any
  // in-flight `scanText` whose promise resolves later won't publish. The
  // counter is global (not per-URI) so a freshly-claimed token can never
  // collide with one stored by a previous invalidated scan for the same
  // URI. This is what prevents stale diagnostics from being re-published
  // after the tab closes (or a newer scan supersedes the in-flight one).
  let scanCounter = 0
  const scanTokens = new Map<string, number>()
  const claimScan = (uri: Uri): number => {
    const token = ++scanCounter
    scanTokens.set(uri.toString(), token)
    return token
  }
  const isLatestScan = (uri: Uri, token: number): boolean =>
    scanTokens.get(uri.toString()) === token
  const invalidateScan = (uri: Uri): void => {
    scanTokens.delete(uri.toString())
  }

  /** True when any workspace folder's `.tokenxrayignore` excludes this doc. */
  const isIgnored = (doc: TextDocument): boolean => {
    // Resolve to the on-disk URI: for notebook cells that's the parent
    // `.ipynb` file. Untitled buffers fall through to "not ignored".
    const sourceUri = notebookFileUri(doc.uri) ?? doc.uri
    if (sourceUri.scheme !== 'file') return false
    const folder = workspace.getWorkspaceFolder(sourceUri)
    if (!folder) return false
    const patterns = ignoreCache.get(folder.uri.toString())
    if (!patterns || patterns.length === 0) return false
    const rel = relativeFor(doc, folder)
    if (!rel) return false
    return matchIgnore(rel, patterns)
  }

  const refresh = async (doc: TextDocument) => {
    // Claim the latest scan slot for this URI up-front so any earlier
    // in-flight scan is invalidated even if we exit through the
    // unsupported / ignored / error paths below.
    const token = claimScan(doc.uri)
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
      // Drop results when our token is no longer the latest: either the
      // tab was closed mid-scan (token invalidated) or another refresh
      // for the same URI raced past us (token superseded).
      if (!isLatestScan(doc.uri, token)) return
      collection.set(doc.uri, dtos.map(dtoToDiagnostic))
    } catch {
      if (isLatestScan(doc.uri, token)) collection.delete(doc.uri)
    }
  }

  const refreshAll = () => {
    // `workspace.textDocuments` can include documents whose tabs have
    // already been closed (VS Code keeps the buffer alive past the tab),
    // so we drop those before rescanning — otherwise `refresh()` would
    // re-publish diagnostics for a file the user can no longer see.
    const openTabs = openTabUriStrings()
    for (const doc of workspace.textDocuments) {
      if (!openTabs.has(effectiveTabUri(doc.uri).toString())) {
        invalidateScan(doc.uri)
        collection.delete(doc.uri)
        continue
      }
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

  // Per-URI debounce timers for change events. A keystroke fires
  // `onDidChangeTextDocument` per character — scanning every one wastes
  // CPU on large files. We coalesce into a single trailing scan; if a
  // newer change arrives during the wait, the existing timer is reset
  // so only the final pause triggers a scan.
  const changeTimers = new Map<string, ReturnType<typeof setTimeout>>()
  const clearChangeTimer = (uriKey: string) => {
    const t = changeTimers.get(uriKey)
    if (t) {
      clearTimeout(t)
      changeTimers.delete(uriKey)
    }
  }
  const scheduleChange = (doc: TextDocument) => {
    if (changeDebounceMs <= 0) {
      void refresh(doc)
      return
    }
    const key = doc.uri.toString()
    clearChangeTimer(key)
    const timer = setTimeout(() => {
      changeTimers.delete(key)
      void refresh(doc)
    }, changeDebounceMs)
    changeTimers.set(key, timer)
  }

  context.subscriptions.push(
    workspace.onDidOpenTextDocument((doc) => void refresh(doc)),
    workspace.onDidChangeTextDocument((e) => scheduleChange(e.document)),
    workspace.onDidCloseTextDocument((doc) => {
      clearChangeTimer(doc.uri.toString())
      invalidateScan(doc.uri)
      collection.delete(doc.uri)
    }),
    // `onDidCloseTextDocument` is not guaranteed to fire when the user
    // closes a tab (VS Code may keep the doc alive), so we also reconcile
    // against the live tab list — anything no longer in any tab gets its
    // diagnostics cleared from the Problems panel AND its in-flight scan
    // invalidated so a slow `scanText` doesn't re-publish stale results.
    window.tabGroups.onDidChangeTabs((event) => {
      if (event.closed.length === 0) return
      const openTabs = openTabUriStrings()
      for (const key of Array.from(scanTokens.keys())) {
        const uri = Uri.parse(key)
        if (!openTabs.has(effectiveTabUri(uri).toString())) {
          clearChangeTimer(key)
          scanTokens.delete(key)
        }
      }
      collection.forEach((uri) => {
        if (!openTabs.has(effectiveTabUri(uri).toString())) {
          collection.delete(uri)
        }
      })
    }),
    workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('tokenXray.respectGitignore')) {
        void refreshOnIgnoreEvent()
        return
      }
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
      if (base === IGNORE_FILE_NAME || base === GITIGNORE_FILE_NAME) {
        void refreshOnIgnoreEvent()
      }
    }),
    {
      dispose: () => {
        for (const t of changeTimers.values()) clearTimeout(t)
        changeTimers.clear()
      },
    }
  )
}
