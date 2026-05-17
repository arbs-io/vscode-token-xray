import {
  Command,
  DiagnosticSeverity,
  Event,
  EventEmitter,
  ExtensionContext,
  ProviderResult,
  Range,
  ThemeIcon,
  TreeDataProvider,
  TreeItem,
  TreeItemCollapsibleState,
  Uri,
  languages,
  window,
  workspace,
} from 'vscode'
import {
  buildTree,
  FindingTreeRange,
  TreeNodeDto,
  WorkspaceFinding,
} from '../core/findingsTree'
import { Severity } from '../core/types'

const DIAGNOSTIC_SOURCE = 'tokenXray'

const SEVERITY_FROM_DIAGNOSTIC: Record<DiagnosticSeverity, Severity | undefined> = {
  [DiagnosticSeverity.Error]: 'error',
  [DiagnosticSeverity.Warning]: 'warning',
  [DiagnosticSeverity.Information]: 'info',
  [DiagnosticSeverity.Hint]: 'info',
}

const SEVERITY_ICON: Record<Severity, ThemeIcon> = {
  error: new ThemeIcon('error'),
  warning: new ThemeIcon('warning'),
  info: new ThemeIcon('info'),
}

/**
 * Tree-data provider that renders Token X-Ray findings (collected from the
 * `tokenXray` diagnostic source across every open document) grouped by
 * analyzer under the activity-bar view container.
 *
 * All ordering / labelling logic lives in `src/core/findingsTree.ts`; this
 * adapter just collects diagnostics, converts them into the pure builder's
 * input shape, and translates the resulting DTOs into `vscode.TreeItem`
 * instances. Clicking a leaf opens the source file and reveals the finding.
 */
export class FindingsTreeViewProvider implements TreeDataProvider<TreeNodeDto> {
  private readonly _onDidChange = new EventEmitter<TreeNodeDto | undefined | void>()
  readonly onDidChangeTreeData: Event<TreeNodeDto | undefined | void> = this._onDidChange.event

  /** Cached root nodes — rebuilt on every refresh. */
  private cachedRoots: TreeNodeDto[] = []

  refresh(): void {
    this.cachedRoots = buildTree(this.collectFindings())
    this._onDidChange.fire()
  }

  getTreeItem(element: TreeNodeDto): TreeItem {
    if (element.kind === 'analyzerRoot') {
      const item = new TreeItem(element.label, TreeItemCollapsibleState.Expanded)
      item.id = element.id
      item.contextValue = 'tokenXray.analyzerRoot'
      item.description = this.describeCounts(element)
      return item
    }
    const item = new TreeItem(element.label, TreeItemCollapsibleState.None)
    item.id = element.id
    item.contextValue = 'tokenXray.finding'
    if (element.severity) {
      item.iconPath = SEVERITY_ICON[element.severity]
    }
    item.command = this.revealCommandFor(element)
    return item
  }

  getChildren(element?: TreeNodeDto): ProviderResult<TreeNodeDto[]> {
    if (!element) return this.cachedRoots
    if (element.kind === 'analyzerRoot') return element.children
    return []
  }

  /** Internal: collect every tokenXray diagnostic across open documents. */
  private collectFindings(): WorkspaceFinding[] {
    const findings: WorkspaceFinding[] = []
    for (const [uri, diagnostics] of languages.getDiagnostics()) {
      for (const diag of diagnostics) {
        if (diag.source !== DIAGNOSTIC_SOURCE) continue
        const severity = SEVERITY_FROM_DIAGNOSTIC[diag.severity] ?? 'info'
        const findingId = typeof diag.code === 'string'
          ? diag.code
          : typeof diag.code === 'number'
            ? String(diag.code)
            : (diag.code && typeof diag.code === 'object' && 'value' in diag.code
              ? String((diag.code as { value: string | number }).value)
              : 'unknown')
        const analyzerId = findingId.split('.')[0] || 'unknown'
        findings.push({
          filePath: this.workspaceRelativePath(uri),
          analyzerId,
          analyzerName: this.titleize(analyzerId),
          finding: {
            id: findingId,
            severity,
            message: diag.message,
          },
          range: rangeFromDiagnosticRange(diag.range),
        })
      }
    }
    return findings
  }

  private workspaceRelativePath(uri: Uri): string {
    if (uri.scheme === 'file') {
      const folder = workspace.getWorkspaceFolder(uri)
      if (folder) {
        const folderPath = folder.uri.fsPath
        const filePath = uri.fsPath
        if (filePath.startsWith(folderPath)) {
          return filePath.slice(folderPath.length).replace(/^[\\/]+/, '')
        }
      }
      return uri.fsPath
    }
    return uri.toString()
  }

  private titleize(analyzerId: string): string {
    if (!analyzerId) return 'Unknown'
    return analyzerId.charAt(0).toUpperCase() + analyzerId.slice(1)
  }

  private describeCounts(node: TreeNodeDto): string | undefined {
    const parts: string[] = []
    if ((node.errorCount ?? 0) > 0) parts.push(`${node.errorCount} error${node.errorCount === 1 ? '' : 's'}`)
    if ((node.warningCount ?? 0) > 0) parts.push(`${node.warningCount} warning${node.warningCount === 1 ? '' : 's'}`)
    if ((node.infoCount ?? 0) > 0) parts.push(`${node.infoCount} info`)
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
      title: 'Open Finding',
      arguments: [uri, { selection }],
    }
  }
}

function rangeFromDiagnosticRange(r: Range): FindingTreeRange {
  return {
    startLine: r.start.line,
    startColumn: r.start.character,
    endLine: r.end.line,
    endColumn: r.end.character,
  }
}

export function registerFindingsTreeViewProvider(context: ExtensionContext): void {
  const provider = new FindingsTreeViewProvider()
  // Seed the initial tree from whatever diagnostics are already published.
  provider.refresh()
  const treeView = window.createTreeView('tokenXray.findings', {
    treeDataProvider: provider,
    showCollapseAll: true,
  })
  context.subscriptions.push(
    treeView,
    languages.onDidChangeDiagnostics(() => provider.refresh())
  )
}
