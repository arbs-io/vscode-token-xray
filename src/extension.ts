import { commands, ExtensionContext, window, workspace } from 'vscode'
import { keySourcesFromConfigDetailed } from './analyzers/jwt/keyLoader'
import { registerInspectCommand } from './contexts/registerInspectCommand'
import { registerShowClaimsetPreviewCommand } from './contexts/registerShowClaimsetPreviewCommand'
import { registerShowJsonPreviewCommand } from './contexts/registerShowJsonPreviewCommand'
import { ScanCache } from './core/scanCache'
import { registerDebugOutputChannel } from './providers/debugOutputChannel'
import { registerDocumentLinksProvider } from './providers/documentLinksProvider'
import { registerDocumentSemanticTokensProvider } from './providers/documentSemanticTokensProvider'
import { registerDocumentSymbolsProvider } from './providers/documentSymbolsProvider'
import { registerFindingsTreeViewProvider } from './providers/findingsTreeViewProvider'
import { registerHoverProvider } from './providers/hoverProvider'
import { registerInlayHintsProvider } from './providers/inlayHintsProvider'
import { registerScanCacheLifecycle } from './providers/scanCacheLifecycle'
import { registerSecretCodeActionsProvider } from './providers/secretCodeActionsProvider'
import { registerSecurityCodeLensProvider } from './providers/securityCodeLensProvider'
import { registerSecurityDiagnosticsProvider } from './providers/securityDiagnosticsProvider'
import { registerStatusBarBadgeProvider } from './providers/statusBarBadgeProvider'

export function activate(context: ExtensionContext) {
  // Create the shared "Token X-Ray" debug output channel up-front so
  // any provider that wants to log can grab a logger via
  // `getDebugLogger`. The channel itself is registered as a
  // disposable on the extension context; the logger is a no-op until
  // the user enables `tokenXray.debug`.
  const debugLog = registerDebugOutputChannel(context)

  // Single per-activation scan cache. Each `(uri, version)` pair is
  // tokenised + analyzed at most once even when several providers
  // consume the result. The lifecycle helper drops entries when docs
  // or tabs close so closed-and-reopened files are scanned fresh.
  const scanCache = new ScanCache({
    onError: (where, analyzerId, err) => {
      const detail = err instanceof Error ? err.message : String(err)
      const label = analyzerId ? `${where}[${analyzerId}]` : where
      debugLog(`ScanCache ${label} failed: ${detail}`)
    },
  })
  registerScanCacheLifecycle(context, scanCache)

  // Generic, content-driven analysis — works on any open document.
  registerSecurityCodeLensProvider(context)
  registerSecurityDiagnosticsProvider(context)
  registerSecretCodeActionsProvider(context)
  registerInlayHintsProvider(context)
  registerDocumentLinksProvider(context)
  registerDocumentSymbolsProvider(context)
  registerFindingsTreeViewProvider(context, scanCache)
  registerStatusBarBadgeProvider(context)
  registerInspectCommand(context)

  // JWT-specific glue for the existing `jwt` language id (semantic colours, hover, title-bar buttons).
  registerDocumentSemanticTokensProvider(context)
  registerHoverProvider(context)
  registerShowClaimsetPreviewCommand(context)
  registerShowJsonPreviewCommand(context)

  // Validate `tokenXray.jwt.keys` and surface any malformed entries.
  // Every issue is logged to the debug channel (machine-parseable trace
  // for power users); the FIRST issue seen per-config-revision also
  // raises a one-shot `showWarningMessage` so users who haven't
  // discovered the debug channel still get a visible signal that their
  // settings.json change didn't take effect. We dedupe by (index +
  // reason) tuple so editing one bad entry doesn't re-toast on every
  // keystroke.
  const seenIssues = new Set<string>()
  const reportKeyConfigIssues = async () => {
    const config = workspace.getConfiguration('tokenXray.jwt')
    const { issues } = keySourcesFromConfigDetailed(config.get<unknown[]>('keys', []))
    if (issues.length === 0) {
      seenIssues.clear()
      return
    }
    for (const issue of issues) {
      debugLog(`tokenXray.jwt.keys[${issue.index}] ignored: ${issue.reason}`)
    }
    const firstUnseen = issues.find(
      (i) => !seenIssues.has(`${i.index}:${i.reason}`)
    )
    if (!firstUnseen) return
    for (const i of issues) seenIssues.add(`${i.index}:${i.reason}`)
    const action = await window.showWarningMessage(
      `Token X-Ray: tokenXray.jwt.keys[${firstUnseen.index}] ignored — ${firstUnseen.reason}`,
      'Open Settings'
    )
    if (action === 'Open Settings') {
      void commands.executeCommand('workbench.action.openSettings', 'tokenXray.jwt.keys')
    }
  }
  void reportKeyConfigIssues()
  context.subscriptions.push(
    workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('tokenXray.jwt.keys')) void reportKeyConfigIssues()
    })
  )
}
