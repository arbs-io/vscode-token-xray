import { ExtensionContext } from 'vscode'
import { registerInspectCommand } from './contexts/registerInspectCommand'
import { registerShowClaimsetPreviewCommand } from './contexts/registerShowClaimsetPreviewCommand'
import { registerShowJsonPreviewCommand } from './contexts/registerShowJsonPreviewCommand'
import { registerDocumentLinksProvider } from './providers/documentLinksProvider'
import { registerDocumentSemanticTokensProvider } from './providers/documentSemanticTokensProvider'
import { registerDocumentSymbolsProvider } from './providers/documentSymbolsProvider'
import { registerHoverProvider } from './providers/hoverProvider'
import { registerInlayHintsProvider } from './providers/inlayHintsProvider'
import { registerSecretCodeActionsProvider } from './providers/secretCodeActionsProvider'
import { registerSecurityCodeLensProvider } from './providers/securityCodeLensProvider'
import { registerSecurityDiagnosticsProvider } from './providers/securityDiagnosticsProvider'

export function activate(context: ExtensionContext) {
  // Generic, content-driven analysis — works on any open document.
  registerSecurityCodeLensProvider(context)
  registerSecurityDiagnosticsProvider(context)
  registerSecretCodeActionsProvider(context)
  registerInlayHintsProvider(context)
  registerDocumentLinksProvider(context)
  registerDocumentSymbolsProvider(context)
  registerInspectCommand(context)

  // JWT-specific glue for the existing `jwt` language id (semantic colours, hover, title-bar buttons).
  registerDocumentSemanticTokensProvider(context)
  registerHoverProvider(context)
  registerShowClaimsetPreviewCommand(context)
  registerShowJsonPreviewCommand(context)
}
