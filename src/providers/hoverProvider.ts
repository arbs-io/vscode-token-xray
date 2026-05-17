import {
  CancellationToken,
  ExtensionContext,
  Hover,
  HoverProvider,
  MarkdownString,
  Position,
  TextDocument,
  Uri,
  languages,
  workspace,
} from 'vscode'
import { buildHoverMarkdown } from '../core/buildHoverMarkdown'
import { createDefaultRegistry } from '../core/defaultRegistry'
import { applyDisableComments, FindingWithLocation } from '../core/disableComments'
import { AnalyzerRegistry } from '../core/registry'
import {
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES,
} from '../core/scanText'
import { scanDocument } from '../core/scanDocument'
import {
  applySeverityOverrides,
  SeverityOverrideMap,
} from '../core/severityOverrides'
import { Match } from '../core/types'
import { LocalStorageService } from '../services/storageService'
import { stringHash } from '../utils/stringHash'

const SUPPORTED_SCHEMES = new Set(['file', 'untitled'])

/**
 * Read the same size guardrail the secrets diagnostics provider honours.
 * We re-use this knob here so that hover never does heavy detection work
 * on huge documents (hover compute is on the user-interaction hot path
 * and must never block).
 */
function readMaxFileSizeBytes(uri: Uri): number {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<number>('secrets.maxFileSizeBytes', DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES)
}

function readRuleSeverity(uri: Uri): SeverityOverrideMap {
  const config = workspace.getConfiguration('tokenXray', uri)
  return config.get<SeverityOverrideMap>('ruleSeverity', {})
}

/**
 * Generic hover provider that runs the full analyzer registry against the
 * document text and surfaces a Markdown preview when the cursor sits inside
 * a detected token range. Works across ALL languages — not just `jwt` —
 * via `scanDocument`.
 *
 * The expensive work is shared with the existing diagnostics + CodeLens
 * providers via `scanDocument`, so cost is bounded by the same byte cap
 * as those providers.
 */
class GenericHoverProvider implements HoverProvider {
  private readonly registry: AnalyzerRegistry = createDefaultRegistry()

  async provideHover(
    document: TextDocument,
    position: Position,
    _token: CancellationToken
  ): Promise<Hover | undefined> {
    if (!SUPPORTED_SCHEMES.has(document.uri.scheme)) return undefined
    const text = document.getText()
    if (!text) return undefined
    const maxBytes = readMaxFileSizeBytes(document.uri)
    if (maxBytes >= 0 && text.length > maxBytes) return undefined

    const cursorOffset = document.offsetAt(position)
    const hits = scanDocument(text, this.registry, { maxBytes })
    const hit = hits.find(
      (h) => cursorOffset >= h.startOffset && cursorOffset <= h.endOffset
    )
    if (!hit) return undefined

    const analyzer = this.registry.get(hit.analyzerId)
    if (!analyzer) return undefined

    const match: Match = {
      text: hit.text,
      range: { start: hit.startOffset, end: hit.endOffset },
    }

    try {
      const result = await Promise.resolve(analyzer.analyze(match))
      // Honour user-configured per-rule severity overrides AND inline
      // `tokenxray-disable-*` directives: drop or rewrite any findings
      // that are silenced / re-graded for this hit's line before we
      // render the hover preview. Order mirrors the registry-boundary
      // sequence in `diagnosticsAcrossRegistry`.
      const overridden = applySeverityOverrides(
        result.findings ?? [],
        readRuleSeverity(document.uri)
      )
      const located: FindingWithLocation[] = overridden.map((finding) => ({
        ...finding,
        startLine: hit.startLine,
      }))
      const kept = applyDisableComments(located, text)
      const filtered = {
        ...result,
        findings: kept.map(({ startLine: _ignored, ...rest }) => rest),
      }
      const md = new MarkdownString(buildHoverMarkdown(filtered))
      md.supportThemeIcons = true
      return new Hover(md)
    } catch {
      return undefined
    }
  }
}

/**
 * Legacy JWT-only hover, kept for the `jwt` language id so the existing
 * webview-driven header/payload preview (powered by stored
 * `joseHeader_*` / `claimsSet_*` values written by the JWT semantic
 * tokens provider) continues to work in the rich JWT editing experience.
 */
function registerLegacyJwtHover(context: ExtensionContext) {
  context.subscriptions.push(
    languages.registerHoverProvider('jwt', {
      provideHover(document, position) {
        const docHash = stringHash(document.uri.toString())
        const storage = new LocalStorageService(context.workspaceState)
        const kind = storage.getValue<string>(`jwtKind_${docHash}`)

        const range = document.getWordRangeAtPosition(position)
        const storageKey =
          range?.start.character === 0 ? `joseHeader_${docHash}` : `claimsSet_${docHash}`
        const value = storage.getValue<object>(storageKey)

        if (kind === 'JWE' && storageKey === `claimsSet_${docHash}`) {
          const md = new MarkdownString(
            '**JWE** — payload is encrypted. Provide a decryption key to inspect contents.'
          )
          return new Hover(md)
        }

        if (!value) return undefined

        return new Hover({
          language: 'json',
          value: JSON.stringify(value, undefined, 4),
        })
      },
    })
  )
}

export function registerHoverProvider(context: ExtensionContext) {
  // 1. Keep the rich JWT-only hover for the `jwt` language id (header /
  //    claimset previews backed by the semantic tokens provider state).
  registerLegacyJwtHover(context)

  // 2. Generic hover for every supported scheme — surfaces SAML / x509 /
  //    JWK / OAuth / cookie / secret / paseto / basicAuth / awsSigv4 /
  //    csr / sshKey / pgp / oidcDiscovery / samlMetadata / httpSignature
  //    detections inside any document.
  context.subscriptions.push(
    languages.registerHoverProvider(
      [{ scheme: 'file' }, { scheme: 'untitled' }],
      new GenericHoverProvider()
    )
  )
}
