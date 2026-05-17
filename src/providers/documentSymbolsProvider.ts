import {
  CancellationToken,
  DocumentSymbol,
  DocumentSymbolProvider,
  ExtensionContext,
  Range,
  SymbolKind,
  TextDocument,
  Uri,
  languages,
  workspace,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import {
  buildDocumentSymbolDtos,
  DocumentSymbolDto,
  DocumentSymbolHit,
  DocumentSymbolKind,
} from '../core/documentSymbols'
import { scanDocument } from '../core/scanDocument'
import { DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES } from '../core/scanText'
import { AnalysisResult, Match } from '../core/types'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])

const SYMBOL_KIND_MAP: Record<DocumentSymbolKind, SymbolKind> = {
  Key: SymbolKind.Key,
  Constant: SymbolKind.Constant,
  Object: SymbolKind.Object,
  String: SymbolKind.String,
}

function readMaxFileSizeBytes(uri: Uri): number {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<number>('secrets.maxFileSizeBytes', DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES)
}

/**
 * Document-symbol provider that surfaces detected security tokens as
 * outline entries in VS Code's "Outline" view (and the Ctrl/Cmd+Shift+O
 * symbol picker).
 *
 * All naming / kind / detail logic lives in
 * `src/core/documentSymbols.ts` so the adapter stays a thin vscode
 * shim: scan the document, run `analyze()` on each hit to grab the first
 * section + findings, hand the lot to `buildDocumentSymbolDtos`, and
 * convert the resulting DTOs to `vscode.DocumentSymbol` instances.
 */
export class SecurityDocumentSymbolsProvider implements DocumentSymbolProvider {
  private readonly registry = createDefaultRegistry()

  async provideDocumentSymbols(
    document: TextDocument,
    _token: CancellationToken
  ): Promise<DocumentSymbol[]> {
    if (!SUPPORTED_SCHEMES.has(document.uri.scheme)) return []

    const text = document.getText()
    if (!text) return []
    const maxBytes = readMaxFileSizeBytes(document.uri)
    if (maxBytes >= 0 && text.length > maxBytes) return []

    const hits = scanDocument(text, this.registry, { maxBytes })
    if (hits.length === 0) return []

    const enriched: DocumentSymbolHit[] = []
    for (const hit of hits) {
      const analyzer = this.registry.get(hit.analyzerId)
      if (!analyzer) continue

      const match: Match = {
        text: hit.text,
        range: { start: hit.startOffset, end: hit.endOffset },
      }

      let result: AnalysisResult
      try {
        result = await Promise.resolve(analyzer.analyze(match))
      } catch {
        continue
      }

      enriched.push({
        analyzerId: hit.analyzerId,
        analyzerName: hit.analyzerName,
        kind: result.kind,
        startLine: hit.startLine,
        startColumn: hit.startColumn,
        endLine: hit.endLine,
        endColumn: hit.endColumn,
        firstSection: result.sections?.[0],
        findings: result.findings,
      })
    }

    return buildDocumentSymbolDtos(enriched).map(toDocumentSymbol)
  }
}

function toDocumentSymbol(dto: DocumentSymbolDto): DocumentSymbol {
  const range = new Range(
    dto.range.startLine,
    dto.range.startColumn,
    dto.range.endLine,
    dto.range.endColumn
  )
  const selectionRange = new Range(
    dto.selectionRange.startLine,
    dto.selectionRange.startColumn,
    dto.selectionRange.endLine,
    dto.selectionRange.endColumn
  )
  return new DocumentSymbol(
    dto.name,
    dto.detail ?? '',
    SYMBOL_KIND_MAP[dto.kind],
    range,
    selectionRange
  )
}

export function registerDocumentSymbolsProvider(context: ExtensionContext) {
  const provider = new SecurityDocumentSymbolsProvider()
  context.subscriptions.push(
    languages.registerDocumentSymbolProvider(
      [{ scheme: 'file' }, { scheme: 'untitled' }],
      provider
    )
  )
}
