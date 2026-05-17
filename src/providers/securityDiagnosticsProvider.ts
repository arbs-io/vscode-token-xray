import { dirname } from 'node:path'
import {
  Diagnostic,
  DiagnosticSeverity,
  ExtensionContext,
  languages,
  Range,
  RelativePattern,
  TextDocument,
  Uri,
  window,
  workspace,
  WorkspaceFolder,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { DiagnosticDto } from '../core/diagnostics'
import { parseIgnoreFile } from '../core/ignoreFile'
import { IgnoreSource, isIgnoredByAnySource } from '../core/ignoreSources'
import {
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES,
  ScanTextMetrics,
  ScanTextSettings,
  scanText,
} from '../core/scanText'
import { SeverityOverrideMap } from '../core/severityOverrides'
import { effectiveTabUri, openTabUriStrings } from '../utils/openTabs'
import {
  effectiveUri,
  fallbackDisplayLabel,
  workspaceRelativeFilename,
} from '../utils/workspacePath'
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

// Path helpers (`filenameFor`, `relativeFor`, `notebookFileUri`) moved
// to `src/utils/workspacePath.ts` so the tree-view provider and any
// future analyzer can share the same notebook → fsPath translation.

/**
 * Read a single ignore file at the root of `folder` and return its
 * parsed pattern list. Missing or unreadable files yield `[]` so the
 * caller can merge multiple sources without per-file error handling.
 *
 * Both `FileSystemError` (FNF — the common case when the file simply
 * doesn't exist) and any other read failure resolve to the same
 * empty-list answer; the diagnostics provider is best-effort about
 * ignore files and never surfaces a parse error to the user.
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
  } catch {
    return []
  }
}

/**
 * Discover the ignore sources for a workspace folder. Always includes
 * `<folder>/.tokenxrayignore`; when `tokenXray.respectGitignore` is
 * true (the default) it also folds in every `.gitignore` found inside
 * the folder (root + nested) via `workspace.findFiles`. Each file
 * becomes its own {@link IgnoreSource} so patterns are matched
 * relative to the file's own directory, matching `git` semantics.
 *
 * `node_modules`, `.git`, and `out` are excluded from the search so
 * `findFiles` doesn't recurse into multi-thousand-file dependency
 * trees on every refresh.
 */
async function loadIgnoreSources(folder: WorkspaceFolder): Promise<IgnoreSource[]> {
  const sources: IgnoreSource[] = []

  const tokenXrayPatterns = await loadPatternsFromFile(folder, IGNORE_FILE_NAME)
  if (tokenXrayPatterns.length > 0) {
    sources.push({ baseDir: folder.uri.fsPath, patterns: tokenXrayPatterns })
  }

  const config = workspace.getConfiguration('tokenXray', folder.uri)
  if (!config.get<boolean>('respectGitignore', true)) return sources

  // Limit to a reasonable depth/file-count so massive monorepos don't
  // pay the discovery cost on every reload. 500 is plenty for typical
  // workspaces; users with more can fall back to `.tokenxrayignore`.
  const gitignoreUris = await workspace.findFiles(
    new RelativePattern(folder, '**/.gitignore'),
    '**/{node_modules,.git,out,dist,coverage}/**',
    500
  )
  for (const uri of gitignoreUris) {
    if (uri.scheme !== 'file') continue
    try {
      const bytes = await workspace.fs.readFile(uri)
      const patterns = parseIgnoreFile(new TextDecoder('utf-8').decode(bytes))
      if (patterns.length === 0) continue
      sources.push({ baseDir: dirname(uri.fsPath), patterns })
    } catch {
      // FNF is the common case (file deleted between discovery and
      // read); we treat any read failure as "no patterns" rather than
      // surfacing an error.
    }
  }
  return sources
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
 * Default trailing-edge debounce window for `onDidChangeTextDocument`
 * events. Tuned so a typing burst (one keystroke per ~70ms) resolves
 * to a single trailing scan once the user pauses. Open/close events
 * bypass this and still scan immediately so the Problems panel
 * populates without lag.
 *
 * Overridable via the `tokenXray.scan.debounceMs` setting (0–2000).
 */
const DEFAULT_CHANGE_DEBOUNCE_MS = 250
const MIN_CHANGE_DEBOUNCE_MS = 0
const MAX_CHANGE_DEBOUNCE_MS = 2000

export interface DiagnosticsProviderOptions {
  /**
   * Overrides the configured debounce. Set to 0 in tests for sync
   * behaviour. When omitted the value is read from
   * `tokenXray.scan.debounceMs` and clamped to a safe range.
   */
  changeDebounceMs?: number
}

function readConfiguredDebounceMs(): number {
  const raw = workspace
    .getConfiguration('tokenXray')
    .get<number>('scan.debounceMs', DEFAULT_CHANGE_DEBOUNCE_MS)
  if (!Number.isFinite(raw)) return DEFAULT_CHANGE_DEBOUNCE_MS
  return Math.min(Math.max(Math.floor(raw), MIN_CHANGE_DEBOUNCE_MS), MAX_CHANGE_DEBOUNCE_MS)
}

export function registerSecurityDiagnosticsProvider(
  context: ExtensionContext,
  options: DiagnosticsProviderOptions = {}
) {
  const registry = createDefaultRegistry()
  const collection = languages.createDiagnosticCollection('tokenXray')
  context.subscriptions.push(collection)
  const debugLog = getDebugLogger(context)
  // Test path supplies an explicit override; production reads the
  // user setting on each activation (and re-reads it on config change
  // below). Held in a mutable ref so the change-event handler can
  // refresh without re-registering listeners.
  let changeDebounceMs = options.changeDebounceMs ?? readConfiguredDebounceMs()

  // Per-workspace-folder ignore-source cache. Each folder maps to its
  // list of {@link IgnoreSource}s (root `.tokenxrayignore`, root +
  // nested `.gitignore`). Refreshed on startup and any time files in
  // the workspace change so adding / editing / deleting an ignore file
  // takes effect without an extension reload.
  const ignoreCache = new Map<string, IgnoreSource[]>()

  const refreshIgnoreCache = async () => {
    const folders = workspace.workspaceFolders ?? []
    ignoreCache.clear()
    for (const folder of folders) {
      const sources = await loadIgnoreSources(folder)
      ignoreCache.set(folder.uri.toString(), sources)
    }
  }

  // Per-URI scan-generation map. `claimScan` issues a globally-unique
  // token + AbortController; `isLatestScan` answers whether that token
  // is still the most recent one for the URI; `invalidateScan` drops
  // the URI's slot and aborts the controller so any in-flight
  // `scanText` whose promise hasn't yet resolved both (a) won't publish
  // and (b) short-circuits its remaining registry walk.
  //
  // The counter is global (not per-URI) so a freshly-claimed token can
  // never collide with one stored by a previous invalidated scan for
  // the same URI. This is what prevents stale diagnostics from being
  // re-published after the tab closes (or a newer scan supersedes the
  // in-flight one).
  interface ScanSlot {
    token: number
    controller: AbortController
  }
  let scanCounter = 0
  const scanSlots = new Map<string, ScanSlot>()
  const claimScan = (uri: Uri): ScanSlot => {
    // Abort the previous in-flight scan for this URI so the analyzer
    // walk it's in the middle of bails out at the next checkpoint
    // instead of running to completion before we drop its result.
    const prior = scanSlots.get(uri.toString())
    if (prior) prior.controller.abort()
    const slot: ScanSlot = { token: ++scanCounter, controller: new AbortController() }
    scanSlots.set(uri.toString(), slot)
    return slot
  }
  const isLatestScan = (uri: Uri, token: number): boolean =>
    scanSlots.get(uri.toString())?.token === token
  const invalidateScan = (uri: Uri): void => {
    const slot = scanSlots.get(uri.toString())
    if (!slot) return
    slot.controller.abort()
    scanSlots.delete(uri.toString())
  }

  /**
   * True when any ignore source (`.tokenxrayignore` or any
   * `.gitignore`) excludes this doc. Each source's patterns are
   * matched against the file's path-relative-to-that-source's-dir, so
   * a `dist/.gitignore` applies to files under `dist/` only.
   */
  const isIgnored = (doc: TextDocument): boolean => {
    // Resolve to the on-disk URI: for notebook cells that's the parent
    // `.ipynb` file. Untitled buffers fall through to "not ignored".
    const sourceUri = effectiveUri(doc)
    if (sourceUri.scheme !== 'file') return false
    const folder = workspace.getWorkspaceFolder(sourceUri)
    if (!folder) return false
    const sources = ignoreCache.get(folder.uri.toString())
    if (!sources || sources.length === 0) return false
    return isIgnoredByAnySource(sourceUri.fsPath, sources)
  }

  const refresh = async (doc: TextDocument) => {
    // Claim the latest scan slot for this URI up-front so any earlier
    // in-flight scan is invalidated (and its AbortSignal fires) even
    // if we exit through the unsupported / ignored / error paths below.
    const slot = claimScan(doc.uri)
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
      const filename = workspaceRelativeFilename(doc)
      // Pretty label for the debug summary: prefer the workspace-
      // relative path, fall back to the URI's basename for untitled
      // buffers / files that aren't inside a workspace folder.
      const debugLabel = filename ?? fallbackDisplayLabel(doc.uri)
      const settingsWithDebug: ScanTextSettings = {
        ...settings,
        signal: slot.controller.signal,
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
      if (!isLatestScan(doc.uri, slot.token)) return
      collection.set(doc.uri, dtos.map(dtoToDiagnostic))
    } catch {
      if (isLatestScan(doc.uri, slot.token)) collection.delete(doc.uri)
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
      for (const key of Array.from(scanSlots.keys())) {
        const uri = Uri.parse(key)
        if (!openTabs.has(effectiveTabUri(uri).toString())) {
          clearChangeTimer(key)
          // Abort the in-flight scan AND drop the slot so a later
          // resolution can't sneak through `isLatestScan`.
          const slot = scanSlots.get(key)
          if (slot) slot.controller.abort()
          scanSlots.delete(key)
        }
      }
      collection.forEach((uri) => {
        if (!openTabs.has(effectiveTabUri(uri).toString())) {
          collection.delete(uri)
        }
      })
    }),
    workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('tokenXray.scan.debounceMs')) {
        // Re-read but keep the explicit test override (caller's `options`
        // wins). When no override is set the new value takes effect on
        // the next change event.
        if (options.changeDebounceMs === undefined) {
          changeDebounceMs = readConfiguredDebounceMs()
        }
      }
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
