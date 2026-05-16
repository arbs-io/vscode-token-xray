import {
  commands,
  ExtensionContext,
  ViewColumn,
  window,
  workspace,
} from 'vscode'
import { augmentWithVerification, buildJwtPanelPayload } from '../analyzers/jwt/panelPayload'
import { keySourcesFromConfig } from '../analyzers/jwt/keyLoader'
import { CookieAnalyzer } from '../analyzers/cookie/analyzer'
import { JwkAnalyzer } from '../analyzers/jwk/analyzer'
import { OAuthTokenAnalyzer } from '../analyzers/oauth/analyzer'
import { SamlAnalyzer } from '../analyzers/saml/analyzer'
import { SecretAnalyzer } from '../analyzers/secrets/analyzer'
import { X509Analyzer } from '../analyzers/x509/analyzer'
import { JwtClaimsetViewerPanel } from '../panels/jwtClaimsetViewerPanel'

async function inspectJwt(context: ExtensionContext, token: string) {
  let payload = buildJwtPanelPayload(token)
  const config = workspace.getConfiguration('tokenXray.jwt')
  if (config.get<boolean>('verifySignature', false)) {
    const keys = keySourcesFromConfig(config.get<unknown[]>('keys', []))
    const issuer = config.get<string>('expectedIssuer', '') || undefined
    const audience = config.get<string>('expectedAudience', '') || undefined
    payload = await augmentWithVerification(payload, token, keys, { issuer, audience })
  }
  JwtClaimsetViewerPanel.render(context.extensionUri, payload)
}

async function inspectGenericAsJson(
  text: string,
  analyzer: { detect: SamlAnalyzer['detect']; analyze: SamlAnalyzer['analyze'] },
  emptyMessage: string
) {
  const [match] = analyzer.detect(text)
  if (!match) {
    window.showWarningMessage(emptyMessage)
    return
  }
  const result = analyzer.analyze(match)
  const doc = await workspace.openTextDocument({
    language: 'json',
    content: JSON.stringify(
      { kind: result.kind, sections: result.sections, findings: result.findings },
      null,
      2
    ),
  })
  await window.showTextDocument(doc, { preview: false, viewColumn: ViewColumn.Beside })
}

export function registerInspectCommand(context: ExtensionContext) {
  context.subscriptions.push(
    commands.registerCommand(
      'tokenXray.inspect',
      async (analyzerId: string, token: string) => {
        if (!analyzerId || !token) {
          window.showWarningMessage('No token provided.')
          return
        }
        try {
          if (analyzerId === 'jwt') {
            await inspectJwt(context, token)
            return
          }
          if (analyzerId === 'saml') {
            await inspectGenericAsJson(token, new SamlAnalyzer(), 'No SAML content detected.')
            return
          }
          if (analyzerId === 'x509') {
            await inspectGenericAsJson(token, new X509Analyzer(), 'No PEM certificate detected.')
            return
          }
          if (analyzerId === 'jwk') {
            await inspectGenericAsJson(token, new JwkAnalyzer(), 'No JWK/JWKS detected.')
            return
          }
          if (analyzerId === 'oauth') {
            await inspectGenericAsJson(token, new OAuthTokenAnalyzer(), 'No known vendor token detected.')
            return
          }
          if (analyzerId === 'cookie') {
            await inspectGenericAsJson(token, new CookieAnalyzer(), 'No Set-Cookie header detected.')
            return
          }
          if (analyzerId === 'secret') {
            await inspectGenericAsJson(token, new SecretAnalyzer(), 'No secret pattern matched.')
            return
          }
          window.showWarningMessage(`No inspector registered for "${analyzerId}".`)
        } catch (e) {
          window.showErrorMessage(`Failed to inspect ${analyzerId}: ${(e as Error).message}`)
        }
      }
    )
  )
}
