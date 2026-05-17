import {
  Diagnostic,
  DiagnosticSeverity,
  ExtensionContext,
  MarkdownString,
  StatusBarAlignment,
  StatusBarItem,
  TextEditor,
  Uri,
  languages,
  window,
} from 'vscode'
import { summarizeFindings } from '../core/summarizeFindings'
import { Finding, Severity } from '../core/types'

const DIAGNOSTIC_SOURCE = 'tokenXray'
const STATUS_BAR_PRIORITY = 100

const SEVERITY_FROM_DIAGNOSTIC: Record<DiagnosticSeverity, Severity> = {
  [DiagnosticSeverity.Error]: 'error',
  [DiagnosticSeverity.Warning]: 'warning',
  [DiagnosticSeverity.Information]: 'info',
  [DiagnosticSeverity.Hint]: 'info',
}

/**
 * Convert the vscode diagnostics for a single document into the pure
 * mapper's `Finding`-ish DTO shape so we can run `summarizeFindings`
 * with no vscode imports in the core layer.
 *
 * Only `tokenXray`-sourced diagnostics are forwarded — the status bar
 * should never reflect findings from other extensions.
 */
function diagnosticsToFindings(diagnostics: readonly Diagnostic[]): Finding[] {
  const out: Finding[] = []
  for (const diag of diagnostics) {
    if (diag.source !== DIAGNOSTIC_SOURCE) continue
    const severity = SEVERITY_FROM_DIAGNOSTIC[diag.severity] ?? 'info'
    const id = typeof diag.code === 'string'
      ? diag.code
      : typeof diag.code === 'number'
        ? String(diag.code)
        : (diag.code && typeof diag.code === 'object' && 'value' in diag.code
          ? String((diag.code as { value: string | number }).value)
          : 'unknown')
    out.push({ id, severity, message: diag.message })
  }
  return out
}

/**
 * Build the multi-line markdown tooltip shown when the user hovers the
 * status bar item. We surface all three severity counts here (even the
 * info one that the label hides) so the badge still leads to that
 * detail with a single mouseover.
 */
function buildTooltip(errors: number, warnings: number, infos: number): MarkdownString {
  const lines: string[] = []
  lines.push('**Token X-Ray findings**')
  lines.push('')
  lines.push(`- Errors: ${errors}`)
  lines.push(`- Warnings: ${warnings}`)
  lines.push(`- Info: ${infos}`)
  lines.push('')
  lines.push('Click to open the Problems panel.')
  const md = new MarkdownString(lines.join('\n'))
  md.isTrusted = false
  return md
}

/**
 * Update the status bar item to reflect the active editor's findings.
 * Hides the item when the document has no tokenXray diagnostics so the
 * bar isn't cluttered with a zero badge.
 */
function refresh(item: StatusBarItem, uri: Uri | undefined): void {
  if (!uri) {
    item.hide()
    return
  }
  const diagnostics = languages.getDiagnostics(uri)
  const findings = diagnosticsToFindings(diagnostics)
  const summary = summarizeFindings(findings)
  if (summary.hidden) {
    item.text = ''
    item.tooltip = undefined
    item.hide()
    return
  }
  item.text = summary.label
  item.tooltip = buildTooltip(summary.errors, summary.warnings, summary.infos)
  item.show()
}

/**
 * Register the status-bar badge provider.
 *
 * Behaviour:
 *   - One `StatusBarItem` aligned to the right, priority 100, owned by
 *     the extension and disposed with the context.
 *   - Recomputes on active-editor change and on `onDidChangeDiagnostics`
 *     for the active document. Both events are necessary: the editor
 *     change fires when the user switches files, the diagnostics event
 *     fires when the secret / token analyzers finish a re-scan.
 *   - Click runs `workbench.actions.view.problems`. VS Code does not
 *     expose a public API to filter the Problems panel by `source`, so
 *     this is the closest user-friendly action the spec calls for.
 */
export function registerStatusBarBadgeProvider(context: ExtensionContext): void {
  const item = window.createStatusBarItem(StatusBarAlignment.Right, STATUS_BAR_PRIORITY)
  item.command = 'workbench.actions.view.problems'
  item.name = 'Token X-Ray'
  item.accessibilityInformation = { label: 'Token X-Ray findings' }
  context.subscriptions.push(item)

  refresh(item, window.activeTextEditor?.document.uri)

  context.subscriptions.push(
    window.onDidChangeActiveTextEditor((editor: TextEditor | undefined) => {
      refresh(item, editor?.document.uri)
    }),
    languages.onDidChangeDiagnostics((event) => {
      const activeUri = window.activeTextEditor?.document.uri
      if (!activeUri) {
        item.hide()
        return
      }
      // The diagnostics event fires for every changed URI; only refresh
      // when the change touches the active document so we don't pay for
      // unrelated background scans.
      const touchesActive = event.uris.some((uri) => uri.toString() === activeUri.toString())
      if (touchesActive) {
        refresh(item, activeUri)
      }
    })
  )
}
