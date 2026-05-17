import { commands, ExtensionContext, Uri, window, workspace } from 'vscode'
import { augmentWithVerification, buildJwtPanelPayload } from '../analyzers/jwt/panelPayload'
import { JwtClaimsetViewerPanel } from '../panels/jwtClaimsetViewerPanel'
import { keySourcesFromConfig } from '../analyzers/jwt/keyLoader'
import { LocalStorageService } from '../services/storageService'
import { stringHash } from '../utils/stringHash'

export function registerShowClaimsetPreviewCommand(context: ExtensionContext) {
  const command = 'tokenXray.showClaimsetPreviewCommand'
  const handler = async (uri: Uri) => {
    const docHash = stringHash(uri.toString())
    const storage = new LocalStorageService(context.workspaceState)
    const token = storage.getValue<string>(`jwtToken_${docHash}`)

    if (!token) {
      window.showWarningMessage('No JWT detected in this document.')
      return
    }

    try {
      let payload = buildJwtPanelPayload(token)
      const config = workspace.getConfiguration('tokenXray.jwt')
      if (config.get<boolean>('verifySignature', false)) {
        const keys = keySourcesFromConfig(config.get<unknown[]>('keys', []))
        const issuer = config.get<string>('expectedIssuer', '') || undefined
        const audience = config.get<string>('expectedAudience', '') || undefined
        payload = await augmentWithVerification(payload, token, keys, { issuer, audience })
      }
      JwtClaimsetViewerPanel.render(context.extensionUri, payload)
    } catch (e) {
      window.showErrorMessage(`Failed to analyze JWT: ${(e as Error).message}`)
    }
  }
  context.subscriptions.push(commands.registerCommand(command, handler))
}
