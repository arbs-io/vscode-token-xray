import {
  CancellationToken,
  CodeLens,
  CodeLensProvider,
  EventEmitter,
  ExtensionContext,
  languages,
  Range,
  TextDocument,
  workspace,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { scanDocument } from '../core/scanDocument'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled', 'vscode-userdata'])

const ICON_FOR: Record<string, string> = {
  jwt: '$(shield)',
  saml: '$(key)',
  x509: '$(verified)',
  jwk: '$(symbol-key)',
  oauth: '$(warning)',
  cookie: '$(circle-large-outline)',
  paseto: '$(shield)',
  basicAuth: '$(lock)',
  awsSigv4: '$(key)',
  csr: '$(file-symlink-file)',
  sshKey: '$(symbol-key)',
  pgp: '$(lock)',
  secret: '$(error)',
}

const TITLE_FOR: Record<string, (text: string) => string> = {
  jwt: (text: string) => {
    const segments = text.split('.').length
    return segments === 5 ? '$(shield) Inspect JWE token' : '$(shield) Inspect JWT token'
  },
  saml: () => '$(key) Inspect SAML assertion',
  x509: () => '$(verified) Inspect X.509 certificate',
  jwk: (text: string) => (/"keys"\s*:/.test(text) ? '$(symbol-key) Inspect JWKS' : '$(symbol-key) Inspect JWK'),
  oauth: () => '$(warning) Inspect vendor token',
  cookie: () => '$(circle-large-outline) Inspect Set-Cookie',
  paseto: () => '$(shield) Inspect PASETO token',
  basicAuth: () => '$(lock) Inspect Basic credentials',
  awsSigv4: () => '$(key) Inspect AWS SigV4',
  csr: () => '$(file-symlink-file) Inspect CSR',
  sshKey: () => '$(symbol-key) Inspect SSH key',
  pgp: () => '$(lock) Inspect PGP block',
  secret: () => '$(error) Inspect secret',
}

export class SecurityCodeLensProvider implements CodeLensProvider {
  private readonly registry = createDefaultRegistry()
  private readonly _onDidChangeCodeLenses = new EventEmitter<void>()
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event

  refresh(): void {
    this._onDidChangeCodeLenses.fire()
  }

  provideCodeLenses(document: TextDocument, _token: CancellationToken): CodeLens[] {
    if (!SUPPORTED_SCHEMES.has(document.uri.scheme)) return []
    const hits = scanDocument(document.getText(), this.registry)
    return hits.map((hit) => {
      const titler = TITLE_FOR[hit.analyzerId] ?? (() => `$(shield) Inspect ${hit.analyzerName}`)
      const range = new Range(hit.startLine, hit.startColumn, hit.endLine, hit.endColumn)
      return new CodeLens(range, {
        title: titler(hit.text),
        command: 'tokenXray.inspect',
        arguments: [hit.analyzerId, hit.text],
        tooltip: `${ICON_FOR[hit.analyzerId] ?? ''} ${hit.analyzerName}`.trim(),
      })
    })
  }
}

export function registerSecurityCodeLensProvider(context: ExtensionContext) {
  const provider = new SecurityCodeLensProvider()
  context.subscriptions.push(
    languages.registerCodeLensProvider(
      [{ scheme: 'file' }, { scheme: 'untitled' }],
      provider
    ),
    workspace.onDidChangeTextDocument(() => provider.refresh())
  )
}
