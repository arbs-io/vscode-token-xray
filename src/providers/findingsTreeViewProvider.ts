import {
  Command,
  Event,
  EventEmitter,
  ExtensionContext,
  ProviderResult,
  Range,
  TextDocument,
  ThemeIcon,
  TreeDataProvider,
  TreeItem,
  TreeItemCollapsibleState,
  Uri,
  languages,
  window,
  workspace,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import {
  buildTokenTree,
  FindingTreeRange,
  TreeNodeDto,
  WorkspaceToken,
} from '../core/findingsTree'
import { ScanCache } from '../core/scanCache'
import { Severity } from '../core/types'
import { effectiveTabUri, openTabUriStrings } from '../utils/openTabs'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled', 'vscode-notebook-cell'])

const SEVERITY_ICON: Record<Severity, ThemeIcon> = {
  error: new ThemeIcon('error'),
  warning: new ThemeIcon('warning'),
  info: new ThemeIcon('info'),
}

/**
 * Tree-data provider that renders Token X-Ray detections (per-token outline
 * with the analyzer's sections + findings) under the activity-bar view
 * container.
 *
 * Layout (one row per detected token across every open document):
 *
 *   JWT (JWS)                  src/auth.ts:5
 *     Header
 *       alg                    HS256
 *       typ                    JWT
 *     Claims
 *       iss                    https://login.microsoftonline.com/.../v2.0
 *       sub                    alice@example.com
 *       exp                    2026-05-19T00:00:00Z
 *     Findings (1)
 *       [error] jwt.alg.none …
 *
 * All ordering / labelling logic lives in `src/core/findingsTree.ts`; this
 * adapter just scans open documents through the analyzer registry,
 * converts the results into the pure builder's input shape, and translates
 * the resulting DTOs into `vscode.TreeItem` instances.
 */
export class FindingsTreeViewProvider implements TreeDataProvider<TreeNodeDto> {
  private readonly registry = createDefaultRegistry()
  private readonly _onDidChange = new EventEmitter<TreeNodeDto | undefined | void>()
  readonly onDidChangeTreeData: Event<TreeNodeDto | undefined | void> = this._onDidChange.event
  private cachedRoots: TreeNodeDto[] = []
  private readonly scanCache: ScanCache

  constructor(scanCache?: ScanCache) {
    // Default to a private cache when none is supplied so direct callers
    // (notably tests) work without DI. In production `extension.ts`
    // hands in the shared instance the diagnostics provider also uses.
    this.scanCache = scanCache ?? new ScanCache()
  }

  refresh(): void {
    this.cachedRoots = buildTokenTree(this.collectTokens())
    this._onDidChange.fire()
  }

  getTreeItem(element: TreeNodeDto): TreeItem {
    const item = new TreeItem(element.label, this.collapsibleStateFor(element))
    item.id = element.id
    item.contextValue = `tokenXray.${element.kind}`
    if (element.description) item.description = element.description

    if (element.kind === 'tokenRoot') {
      item.iconPath = this.severityIconFor(element)
      item.tooltip = this.describeCounts(element)
      item.command = this.revealCommandFor(element)
    } else if (element.kind === 'finding' && element.severity) {
      item.iconPath = SEVERITY_ICON[element.severity]
      item.tooltip = `${element.findingId ?? ''}\n${element.message ?? ''}`.trim()
      item.command = this.revealCommandFor(element)
    } else if (element.kind === 'sectionRow') {
      item.tooltip = element.rowDescription
    }

    return item
  }

  getChildren(element?: TreeNodeDto): ProviderResult<TreeNodeDto[]> {
    if (!element) return this.cachedRoots
    return element.children
  }

  private collectTokens(): WorkspaceToken[] {
    // `workspace.textDocuments` can hold "ghost" documents whose tabs were
    // closed (VS Code is allowed to keep the TextDocument alive after the
    // tab disappears), so we cross-reference against the live tab list to
    // drop their tokens from the tree.
    const openTabs = openTabUriStrings()
    const tokens: WorkspaceToken[] = []
    for (const doc of workspace.textDocuments) {
      if (!SUPPORTED_SCHEMES.has(doc.uri.scheme)) continue
      if (!openTabs.has(effectiveTabUri(doc.uri).toString())) continue
      tokens.push(...this.scanDocumentTokens(doc))
    }
    return tokens
  }

  private scanDocumentTokens(doc: TextDocument): WorkspaceToken[] {
    // The cache owns the scanDocument + per-match analyze pipeline.
    // We just attach the workspace-relative `filePath` on the way out
    // — the cache is path-agnostic so workspace-folder changes don't
    // force re-analysis.
    const cached = this.scanCache.getTokens({
      uriKey: doc.uri.toString(),
      version: doc.version,
      text: doc.getText(),
      registry: this.registry,
    })
    const filePath = this.workspaceRelativePath(doc.uri)
    return cached.map((t) => ({
      filePath,
      analyzerId: t.analyzerId,
      analyzerName: t.analyzerName,
      kind: t.kind,
      range: t.range,
      sections: t.sections,
      findings: t.findings,
    }))
  }

  private workspaceRelativePath(uri: Uri): string {
    const effective = notebookFileUri(uri) ?? uri
    if (effective.scheme === 'file') {
      const folder = workspace.getWorkspaceFolder(effective)
      if (folder) {
        const folderPath = folder.uri.fsPath
        const filePath = effective.fsPath
        if (filePath.startsWith(folderPath)) {
          return filePath.slice(folderPath.length).replace(/^[\\/]+/, '')
        }
      }
      return effective.fsPath
    }
    return effective.toString()
  }

  private collapsibleStateFor(element: TreeNodeDto): TreeItemCollapsibleState {
    if (element.kind === 'tokenRoot') return TreeItemCollapsibleState.Collapsed
    if (element.kind === 'sectionGroup') return TreeItemCollapsibleState.Collapsed
    if (element.kind === 'findingsGroup') return TreeItemCollapsibleState.Expanded
    return TreeItemCollapsibleState.None
  }

  private severityIconFor(element: TreeNodeDto): ThemeIcon {
    if ((element.errorCount ?? 0) > 0) return SEVERITY_ICON.error
    if ((element.warningCount ?? 0) > 0) return SEVERITY_ICON.warning
    if ((element.infoCount ?? 0) > 0) return SEVERITY_ICON.info
    return new ThemeIcon('symbol-key')
  }

  private describeCounts(element: TreeNodeDto): string | undefined {
    const parts: string[] = []
    if ((element.errorCount ?? 0) > 0) {
      parts.push(`${element.errorCount} error${element.errorCount === 1 ? '' : 's'}`)
    }
    if ((element.warningCount ?? 0) > 0) {
      parts.push(`${element.warningCount} warning${element.warningCount === 1 ? '' : 's'}`)
    }
    if ((element.infoCount ?? 0) > 0) parts.push(`${element.infoCount} info`)
    return parts.length === 0 ? undefined : parts.join(', ')
  }

  private revealCommandFor(element: TreeNodeDto): Command | undefined {
    if (!element.filePath || !element.range) return undefined
    const folder = workspace.workspaceFolders?.[0]
    const uri = folder
      ? Uri.joinPath(folder.uri, element.filePath)
      : Uri.file(element.filePath)
    const selection = new Range(
      element.range.startLine,
      element.range.startColumn,
      element.range.endLine,
      element.range.endColumn
    )
    return {
      command: 'vscode.open',
      title: 'Open Token',
      arguments: [uri, { selection }],
    }
  }
}

function notebookFileUri(uri: Uri): Uri | undefined {
  if (uri.scheme !== 'vscode-notebook-cell') return undefined
  if (!uri.path) return undefined
  return uri.with({ scheme: 'file', fragment: '' })
}

// Keeping this here only because `FindingTreeRange` is the shared shape the
// builder consumes; the function is small enough not to warrant a util file.
export function rangeFromVscodeRange(r: Range): FindingTreeRange {
  return {
    startLine: r.start.line,
    startColumn: r.start.character,
    endLine: r.end.line,
    endColumn: r.end.character,
  }
}

const REFRESH_DEBOUNCE_MS = 50

export function registerFindingsTreeViewProvider(
  context: ExtensionContext,
  scanCache?: ScanCache
): void {
  const provider = new FindingsTreeViewProvider(scanCache)
  provider.refresh()
  const treeView = window.createTreeView('tokenXray.findings', {
    treeDataProvider: provider,
    showCollapseAll: true,
  })

  // Coalesce rapid events (a keystroke fires onDidChangeTextDocument
  // plus a follow-up onDidChangeDiagnostics) into a single rebuild on
  // the trailing edge. 50ms is short enough to feel instant and long
  // enough to absorb a burst of paired events.
  let refreshTimer: ReturnType<typeof setTimeout> | undefined
  const scheduleRefresh = () => {
    if (refreshTimer) clearTimeout(refreshTimer)
    refreshTimer = setTimeout(() => {
      refreshTimer = undefined
      provider.refresh()
    }, REFRESH_DEBOUNCE_MS)
  }

  // Re-scan on document open/change/close, on diagnostic refreshes (which
  // happen after the secret scanner runs), and on tab open/close. The tab
  // listener catches "user closed the tab but VS Code kept the doc in
  // memory" — `onDidCloseTextDocument` is not guaranteed to fire in that
  // case (see the API docs note). `event.changed` is intentionally ignored
  // because it covers active-state / dirty-state flips that don't affect
  // which tokens the tree should show.
  context.subscriptions.push(
    treeView,
    workspace.onDidOpenTextDocument(scheduleRefresh),
    workspace.onDidCloseTextDocument(scheduleRefresh),
    workspace.onDidChangeTextDocument(scheduleRefresh),
    languages.onDidChangeDiagnostics(scheduleRefresh),
    window.tabGroups.onDidChangeTabs((event) => {
      if (event.opened.length === 0 && event.closed.length === 0) return
      scheduleRefresh()
    }),
    {
      dispose: () => {
        if (refreshTimer) clearTimeout(refreshTimer)
      },
    }
  )
}
