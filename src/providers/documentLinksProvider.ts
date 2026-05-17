import {
  CancellationToken,
  DocumentLink,
  DocumentLinkProvider,
  ExtensionContext,
  Range,
  TextDocument,
  Uri,
  languages,
  workspace,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { extractDocumentLinks, HitRange } from '../core/documentLinks'
import { scanDocument } from '../core/scanDocument'
import { DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES } from '../core/scanText'
import { AnalysisResult, Match } from '../core/types'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])

function readMaxFileSizeBytes(uri: Uri): number {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<number>('secrets.maxFileSizeBytes', DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES)
}

/**
 * Document-link provider that makes URLs surfaced by the analyzers
 * (finding `docUrl`s and `iss` claim values) clickable inside any source
 * file. The provider is a thin vscode adapter — all the URL extraction
 * logic lives in `src/core/documentLinks.ts` so it can be unit-tested
 * without spinning up a vscode host.
 *
 * The adapter scans the document with the shared analyzer registry,
 * runs `analyze()` on each detected hit, hands the result to
 * `extractDocumentLinks`, and converts the resulting DTOs to
 * `vscode.DocumentLink` instances anchored at the full hit range.
 */
export class SecurityDocumentLinksProvider implements DocumentLinkProvider {
  private readonly registry = createDefaultRegistry()

  async provideDocumentLinks(
    document: TextDocument,
    _token: CancellationToken
  ): Promise<DocumentLink[]> {
    if (!SUPPORTED_SCHEMES.has(document.uri.scheme)) return []

    const text = document.getText()
    if (!text) return []
    const maxBytes = readMaxFileSizeBytes(document.uri)
    if (maxBytes >= 0 && text.length > maxBytes) return []

    const hits = scanDocument(text, this.registry, { maxBytes })
    const links: DocumentLink[] = []

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

      const hitRange: HitRange = {
        startLine: hit.startLine,
        startColumn: hit.startColumn,
        endLine: hit.endLine,
        endColumn: hit.endColumn,
      }

      for (const dto of extractDocumentLinks(result, hitRange, hit.text)) {
        try {
          const link = new DocumentLink(
            new Range(
              dto.range.startLine,
              dto.range.startColumn,
              dto.range.endLine,
              dto.range.endColumn
            ),
            Uri.parse(dto.target)
          )
          links.push(link)
        } catch {
          // Skip URLs that vscode refuses to parse — extractDocumentLinks
          // already filters to `https://` strings so this is defensive only.
        }
      }
    }

    return links
  }
}

export function registerDocumentLinksProvider(context: ExtensionContext) {
  const provider = new SecurityDocumentLinksProvider()
  context.subscriptions.push(
    languages.registerDocumentLinkProvider(
      [{ scheme: 'file' }, { scheme: 'untitled' }],
      provider
    )
  )
}
