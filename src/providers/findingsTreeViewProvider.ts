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
import { scanDocument } from '../core/scanDocument'
import { Match, Severity } from '../core/types'

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
    const tokens: WorkspaceToken[] = []
    for (const doc of workspace.textDocuments) {
      if (!SUPPORTED_SCHEMES.has(doc.uri.scheme)) continue
      tokens.push(...this.scanDocumentTokens(doc))
    }
    return tokens
  }

  private scanDocumentTokens(doc: TextDocument): WorkspaceToken[] {
    let hits: ReturnType<typeof scanDocument>
    try {
      hits = scanDocument(doc.getText(), this.registry)
    } catch {
      return []
    }
    const out: WorkspaceToken[] = []
    const filePath = this.workspaceRelativePath(doc.uri)
    for (const hit of hits) {
      const analyzer = this.registry.get(hit.analyzerId)
      if (!analyzer) continue
      const match: Match = {
        text: hit.text,
        range: { start: hit.startOffset, end: hit.endOffset },
      }
      try {
        const result = analyzer.analyze(match)
        // `analyze` may be sync or return a Promise; we ignore async results to
        // keep refresh() synchronous. All shipped analyzers are sync.
        if (result instanceof Promise) continue
        out.push({
          filePath,
          analyzerId: hit.analyzerId,
          analyzerName: hit.analyzerName,
          kind: result.kind ?? '',
          range: {
            startLine: hit.startLine,
            startColumn: hit.startColumn,
            endLine: hit.endLine,
            endColumn: hit.endColumn,
          },
          sections: result.sections ?? [],
          findings: result.findings ?? [],
        })
      } catch {
        // skip on analyze failure
      }
    }
    return out
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

export function registerFindingsTreeViewProvider(context: ExtensionContext): void {
  const provider = new FindingsTreeViewProvider()
  provider.refresh()
  const treeView = window.createTreeView('tokenXray.findings', {
    treeDataProvider: provider,
    showCollapseAll: true,
  })
  // Re-scan on document open/change/close and on diagnostic refreshes (which
  // happen after the secret scanner runs — useful for keeping the tree in sync
  // when nothing else fires a text-document event).
  context.subscriptions.push(
    treeView,
    workspace.onDidOpenTextDocument(() => provider.refresh()),
    workspace.onDidCloseTextDocument(() => provider.refresh()),
    workspace.onDidChangeTextDocument(() => provider.refresh()),
    languages.onDidChangeDiagnostics(() => provider.refresh())
  )
}
