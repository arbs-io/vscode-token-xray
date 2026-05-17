import {
  CancellationToken,
  DocumentSemanticTokensProvider,
  ExtensionContext,
  languages,
  SemanticTokens,
  SemanticTokensBuilder,
  SemanticTokensLegend,
  TextDocument,
} from 'vscode'

import {
  ALL_JWT_SEMANTIC_TOKEN_TYPES,
  JwtSemanticTokenType,
  parseJwtTokens,
} from '../analyzers/jwt/semanticParser'
import { decodeJwt, detectJwtKind } from '../analyzers/jwt/decoder'
import { LocalStorageService } from '../services/storageService'
import { stringHash } from '../utils/stringHash'

const TOKEN_INDEX = new Map<JwtSemanticTokenType, number>(
  ALL_JWT_SEMANTIC_TOKEN_TYPES.map((t, i) => [t, i])
)

export function registerDocumentSemanticTokensProvider(context: ExtensionContext) {
  const provider = new JwtDocumentSemanticTokensProvider(context)
  context.subscriptions.push(
    languages.registerDocumentSemanticTokensProvider({ language: 'jwt' }, provider, provider.legend)
  )
}

export class JwtDocumentSemanticTokensProvider implements DocumentSemanticTokensProvider {
  readonly legend = new SemanticTokensLegend(ALL_JWT_SEMANTIC_TOKEN_TYPES as unknown as string[])

  constructor(private readonly _context: ExtensionContext) {}

  async provideDocumentSemanticTokens(
    document: TextDocument,
    _token: CancellationToken
  ): Promise<SemanticTokens> {
    const text = document.getText()
    const tokens = parseJwtTokens(text)

    const builder = new SemanticTokensBuilder()
    for (const t of tokens) {
      builder.push(t.line, t.startCharacter, t.length, TOKEN_INDEX.get(t.tokenType) ?? 0)
    }

    const docHash = stringHash(document.uri.toString())
    const storageManager = new LocalStorageService(this._context.workspaceState)
    const firstLine = text.split(/\r\n|\r|\n/)[0]?.trim() ?? ''
    const kind = detectJwtKind(firstLine)
    if (kind === 'JWS' || kind === 'JWE') {
      try {
        const decoded = decodeJwt(firstLine)
        storageManager.setValue<object | undefined>(`joseHeader_${docHash}`, decoded.header)
        storageManager.setValue<object | undefined>(`claimsSet_${docHash}`, decoded.payload)
        storageManager.setValue<string>(`jwtKind_${docHash}`, decoded.kind)
        storageManager.setValue<string>(`jwtToken_${docHash}`, firstLine)
      } catch {
        storageManager.setValue<object | undefined>(`joseHeader_${docHash}`, undefined)
        storageManager.setValue<object | undefined>(`claimsSet_${docHash}`, undefined)
        storageManager.setValue<string | undefined>(`jwtToken_${docHash}`, undefined)
      }
    }

    return builder.build()
  }
}
