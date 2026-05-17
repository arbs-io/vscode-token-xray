import { ExtensionContext, workspace } from 'vscode'
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

  // Validate `tokenXray.jwt.keys` and surface any malformed entries through
  // the debug output channel. Without this the user has no signal when
  // settings.json contains a typo (entries are silently dropped at
  // verification time). We re-check whenever the user edits the setting so
  // feedback is immediate.
  const reportKeyConfigIssues = () => {
    const config = workspace.getConfiguration('tokenXray.jwt')
    const { issues } = keySourcesFromConfigDetailed(config.get<unknown[]>('keys', []))
    for (const issue of issues) {
      debugLog(`tokenXray.jwt.keys[${issue.index}] ignored: ${issue.reason}`)
    }
  }
  reportKeyConfigIssues()
  context.subscriptions.push(
    workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('tokenXray.jwt.keys')) reportKeyConfigIssues()
    })
  )
}
