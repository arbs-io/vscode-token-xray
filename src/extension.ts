import { ExtensionContext } from 'vscode'
import { registerInspectCommand } from './contexts/registerInspectCommand'
import { registerShowClaimsetPreviewCommand } from './contexts/registerShowClaimsetPreviewCommand'
import { registerShowJsonPreviewCommand } from './contexts/registerShowJsonPreviewCommand'
import { registerDebugOutputChannel } from './providers/debugOutputChannel'
import { registerDocumentLinksProvider } from './providers/documentLinksProvider'
import { registerDocumentSemanticTokensProvider } from './providers/documentSemanticTokensProvider'
import { registerDocumentSymbolsProvider } from './providers/documentSymbolsProvider'
import { registerFindingsTreeViewProvider } from './providers/findingsTreeViewProvider'
import { registerHoverProvider } from './providers/hoverProvider'
import { registerInlayHintsProvider } from './providers/inlayHintsProvider'
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
  registerDebugOutputChannel(context)

  // Generic, content-driven analysis — works on any open document.
  registerSecurityCodeLensProvider(context)
  registerSecurityDiagnosticsProvider(context)
  registerSecretCodeActionsProvider(context)
  registerInlayHintsProvider(context)
  registerDocumentLinksProvider(context)
  registerDocumentSymbolsProvider(context)
  registerFindingsTreeViewProvider(context)
  registerStatusBarBadgeProvider(context)
  registerInspectCommand(context)

  // JWT-specific glue for the existing `jwt` language id (semantic colours, hover, title-bar buttons).
  registerDocumentSemanticTokensProvider(context)
  registerHoverProvider(context)
  registerShowClaimsetPreviewCommand(context)
  registerShowJsonPreviewCommand(context)
}
