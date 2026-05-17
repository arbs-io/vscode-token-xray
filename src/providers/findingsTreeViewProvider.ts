import {
  Command,
  Event,
  EventEmitter,
  ExtensionContext,
  MarkdownString,
  ProviderResult,
  Range,
  TextDocument,
  ThemeColor,
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
import { workspaceRelativeFilename } from '../utils/workspacePath'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled', 'vscode-notebook-cell'])

const SEVERITY_COLOR: Record<Severity, ThemeColor> = {
  error: new ThemeColor('list.errorForeground'),
  warning: new ThemeColor('list.warningForeground'),
  info: new ThemeColor('charts.blue'),
}

const SEVERITY_ICON: Record<Severity, ThemeIcon> = {
  error: new ThemeIcon('error', SEVERITY_COLOR.error),
  warning: new ThemeIcon('warning', SEVERITY_COLOR.warning),
  info: new ThemeIcon('info', SEVERITY_COLOR.info),
}

/**
 * Per-analyzer codicon for the token-row glyph. Picked so each
 * detector class is distinguishable at a glance without having to read
 * the analyzer name. Falls back to a generic key when an analyzer id
 * isn't in the table (e.g. third-party analyzers registered later).
 */
const ANALYZER_ICON: Record<string, string> = {
  jwt: 'key',
  jwk: 'symbol-key',
  saml: 'shield',
  samlMetadata: 'book',
  x509: 'verified',
  csr: 'request-changes',
  oauth: 'account',
  oidcDiscovery: 'link-external',
  cookie: 'database',
  paseto: 'symbol-keyword',
  basicAuth: 'lock',
  awsSigv4: 'cloud',
  pgp: 'gist-secret',
  sshKey: 'terminal',
  httpSignature: 'note',
  secret: 'eye-closed',
}

/**
 * Codicon for common section titles emitted by the analyzers. Matched
 * case-insensitively against the section's first word so titles like
 * "Cookie: session" still pick up the "cookie" entry. Untitled or
 * unrecognised sections fall back to `list-unordered`.
 */
const SECTION_ICON: Record<string, string> = {
  header: 'symbol-namespace',
  jose: 'symbol-namespace',
  claims: 'symbol-property',
  payload: 'symbol-property',
  certificate: 'verified',
  cookie: 'database',
  credentials: 'account',
  signature: 'edit',
  block: 'archive',
  token: 'key',
  endpoints: 'link',
  capabilities: 'list-flat',
  overview: 'list-tree',
  subject: 'symbol-class',
  key: 'symbol-key',
  metadata: 'book',
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
      item.iconPath = this.tokenRootIcon(element)
      item.description = this.tokenRootDescription(element)
      item.tooltip = this.tokenRootTooltip(element)
      item.command = this.revealCommandFor(element)
    } else if (element.kind === 'finding' && element.severity) {
      item.iconPath = SEVERITY_ICON[element.severity]
      item.tooltip = `${element.findingId ?? ''}\n${element.message ?? ''}`.trim()
      item.command = this.revealCommandFor(element)
    } else if (element.kind === 'sectionGroup') {
      item.iconPath = this.sectionGroupIcon(element)
    } else if (element.kind === 'sectionRow') {
      item.iconPath = new ThemeIcon('dash')
      item.tooltip = element.rowDescription
    } else if (element.kind === 'findingsGroup') {
      item.iconPath = new ThemeIcon('bell-dot', SEVERITY_COLOR.warning)
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
    // The tree-view label needs a string — fall back to the URI when
    // the document is untitled / off-workspace (the path util returns
    // `undefined` in that case).
    const filePath = workspaceRelativeFilename(doc) ?? doc.uri.toString()
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

  private collapsibleStateFor(element: TreeNodeDto): TreeItemCollapsibleState {
    if (element.kind === 'tokenRoot') return TreeItemCollapsibleState.Collapsed
    if (element.kind === 'sectionGroup') return TreeItemCollapsibleState.Collapsed
    if (element.kind === 'findingsGroup') return TreeItemCollapsibleState.Expanded
    return TreeItemCollapsibleState.None
  }

  /**
   * Token-row glyph: the analyzer's signature codicon, tinted with the
   * worst-severity colour so a quick scan tells the user *both* what
   * the detector is and how serious the findings are. Falls back to
   * `key` when the analyzer id isn't in {@link ANALYZER_ICON} (e.g.
   * third-party analyzers registered via DI in tests).
   */
  private tokenRootIcon(element: TreeNodeDto): ThemeIcon {
    const iconId = ANALYZER_ICON[element.analyzerId ?? ''] ?? 'key'
    const tint = this.worstSeverityColor(element)
    return tint ? new ThemeIcon(iconId, tint) : new ThemeIcon(iconId)
  }

  /**
   * Inline "description" text shown to the right of the token label:
   * the file location plus a compact severity badge when findings
   * exist. Keeps the per-row width tight so the activity-bar view
   * doesn't wrap on narrow sidebars.
   */
  private tokenRootDescription(element: TreeNodeDto): string | undefined {
    const location = element.description
    const counts = this.compactCountBadge(element)
    if (location && counts) return `${location} · ${counts}`
    return location ?? counts
  }

  /**
   * Multi-line markdown tooltip for the token row. Shown on hover —
   * doesn't replace the visible icon/description, so the extra detail
   * (full counts breakdown) lives here instead of cluttering the tree.
   */
  private tokenRootTooltip(element: TreeNodeDto): MarkdownString | undefined {
    const lines: string[] = []
    const name = element.analyzerName ?? 'Token'
    lines.push(`**${name}**`)
    if (element.description) lines.push(`\`${element.description}\``)
    const breakdown = this.describeCounts(element)
    if (breakdown) lines.push(breakdown)
    if (lines.length === 1) return undefined
    const md = new MarkdownString(lines.join('\n\n'))
    md.isTrusted = false
    return md
  }

  private worstSeverityColor(element: TreeNodeDto): ThemeColor | undefined {
    if ((element.errorCount ?? 0) > 0) return SEVERITY_COLOR.error
    if ((element.warningCount ?? 0) > 0) return SEVERITY_COLOR.warning
    if ((element.infoCount ?? 0) > 0) return SEVERITY_COLOR.info
    return undefined
  }

  private compactCountBadge(element: TreeNodeDto): string | undefined {
    const e = element.errorCount ?? 0
    const w = element.warningCount ?? 0
    const i = element.infoCount ?? 0
    if (e + w + i === 0) return undefined
    const parts: string[] = []
    if (e > 0) parts.push(`${e}E`)
    if (w > 0) parts.push(`${w}W`)
    if (i > 0) parts.push(`${i}I`)
    return parts.join(' ')
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

  /**
   * Section header glyph: matches the section title's first significant
   * word against {@link SECTION_ICON}. We strip leading punctuation
   * ("Cookie: name" → "cookie") so analyzer-supplied titles keep their
   * cosmetic suffix without losing the icon mapping.
   */
  private sectionGroupIcon(element: TreeNodeDto): ThemeIcon {
    const first = (element.label ?? '')
      .replace(/^[^A-Za-z]+/, '')
      .split(/[\s:&]+/)[0]
      ?.toLowerCase()
    const iconId = (first && SECTION_ICON[first]) || 'list-unordered'
    return new ThemeIcon(iconId)
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
