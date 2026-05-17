import {
  CancellationToken,
  ExtensionContext,
  InlayHint,
  InlayHintKind,
  InlayHintsProvider,
  MarkdownString,
  Position,
  Range,
  TextDocument,
  Uri,
  languages,
  workspace,
} from 'vscode'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { applyDisableComments, FindingWithLocation } from '../core/disableComments'
import { findingsToInlayDtos, HitRange } from '../core/inlayHints'
import {
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES,
} from '../core/scanText'
import { scanDocument } from '../core/scanDocument'
import {
  applySeverityOverrides,
  SeverityOverrideMap,
} from '../core/severityOverrides'
import { AnalysisResult, Match } from '../core/types'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])

function isInlayHintsEnabled(uri: Uri): boolean {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<boolean>('inlayHints.enabled', true)
}

function readMaxFileSizeBytes(uri: Uri): number {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<number>('secrets.maxFileSizeBytes', DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES)
}

function readRuleSeverity(uri: Uri): SeverityOverrideMap {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<SeverityOverrideMap>('ruleSeverity', {})
}

/**
 * Inlay-hint provider that decorates detected security tokens with
 * compact inline annotations (e.g. `[expired]`, `[exp in 3d]`,
 * `[RSA-1024]`, `[live]`, `[secret]`).
 *
 * All heuristic logic lives in `src/core/inlayHints.ts` so the provider
 * itself is a thin vscode adapter: scan the document, run `analyze()`
 * on each detected token that overlaps the requested range, hand the
 * findings + range to the pure mapper, and translate the resulting
 * DTOs into `vscode.InlayHint` instances.
 */
export class SecurityInlayHintsProvider implements InlayHintsProvider {
  private readonly registry = createDefaultRegistry()

  async provideInlayHints(
    document: TextDocument,
    range: Range,
    _token: CancellationToken
  ): Promise<InlayHint[]> {
    if (!SUPPORTED_SCHEMES.has(document.uri.scheme)) return []
    if (!isInlayHintsEnabled(document.uri)) return []

    const text = document.getText()
    if (!text) return []
    const maxBytes = readMaxFileSizeBytes(document.uri)
    if (maxBytes >= 0 && text.length > maxBytes) return []

    const rangeStartOffset = document.offsetAt(range.start)
    const rangeEndOffset = document.offsetAt(range.end)

    const hits = scanDocument(text, this.registry, { maxBytes })
    const hints: InlayHint[] = []

    for (const hit of hits) {
      // Only emit hints for tokens that overlap the visible range so we
      // do not pay for analysis we cannot render.
      if (hit.endOffset < rangeStartOffset || hit.startOffset > rangeEndOffset) continue
      const result = await this.analyzeHit(hit)
      if (!result) continue
      const filteredResult = filterByOverridesAndDisableComments(
        result,
        readRuleSeverity(document.uri),
        text,
        hit.startLine
      )
      const hitRange: HitRange = {
        startLine: hit.startLine,
        startColumn: hit.startColumn,
        endLine: hit.endLine,
        endColumn: hit.endColumn,
      }
      for (const dto of findingsToInlayDtos(filteredResult, hitRange)) {
        hints.push(makeInlayHint(dto))
      }
    }

    return hints
  }

  private async analyzeHit(hit: { analyzerId: string; text: string; startOffset: number; endOffset: number }): Promise<AnalysisResult | undefined> {
    const analyzer = this.registry.get(hit.analyzerId)
    if (!analyzer) return undefined
    const match: Match = { text: hit.text, range: { start: hit.startOffset, end: hit.endOffset } }
    try {
      return await Promise.resolve(analyzer.analyze(match))
    } catch {
      return undefined
    }
  }
}

function filterByOverridesAndDisableComments(
  result: AnalysisResult,
  ruleSeverity: SeverityOverrideMap,
  text: string,
  startLine: number
): AnalysisResult {
  const overridden = applySeverityOverrides(result.findings ?? [], ruleSeverity)
  const located: FindingWithLocation[] = overridden.map((finding) => ({ ...finding, startLine }))
  const kept = applyDisableComments(located, text)
  return {
    ...result,
    findings: kept.map(({ startLine: _ignored, ...rest }) => rest),
  }
}

function makeInlayHint(dto: ReturnType<typeof findingsToInlayDtos>[number]): InlayHint {
  const hint = new InlayHint(
    new Position(dto.position.line, dto.position.column),
    ` ${dto.label}`,
    InlayHintKind.Type
  )
  if (dto.tooltip) hint.tooltip = new MarkdownString(dto.tooltip)
  hint.paddingLeft = true
  return hint
}

export function registerInlayHintsProvider(context: ExtensionContext) {
  const provider = new SecurityInlayHintsProvider()
  context.subscriptions.push(
    languages.registerInlayHintsProvider(
      [{ scheme: 'file' }, { scheme: 'untitled' }],
      provider
    )
  )
}
