import { Finding, Match, Section } from './types'
import { AnalyzerRegistry } from './registry'
import { scanDocument } from './scanDocument'
import { FindingTreeRange } from './findingsTree'

/**
 * One analyzed token in cache form — everything the providers need to
 * render the tree or derive diagnostics except `filePath`, which is a
 * workspace-relative display string the cache shouldn't own.
 *
 * Mirrors `WorkspaceToken` minus that field. Providers re-attach the
 * path after retrieval so workspace-folder changes don't invalidate
 * the cache.
 */
export interface CachedToken {
  analyzerId: string
  analyzerName: string
  /** `AnalysisResult.kind` — short kind label like "JWS", "cert (DER)". */
  kind: string
  range: FindingTreeRange
  sections: Section[]
  findings: Finding[]
}

export interface ScanCacheInputs {
  /** Stable identifier for the document (typically `doc.uri.toString()`). */
  uriKey: string
  /** Monotonically-increasing document version (typically `doc.version`). */
  version: number
  text: string
  registry: AnalyzerRegistry
}

/**
 * Per-document scan cache. The tree view and (in step 2) the diagnostics
 * provider both consult one shared instance so each `(uri, version)`
 * pair is tokenised + analyzed exactly once — even though both
 * providers fire scans on the same event stream today.
 *
 * Cache keys are `${uriKey}@${version}`. When a fresher version arrives
 * older entries for the same URI are evicted, so the cache never holds
 * stale snapshots for a file. Async analyzers are skipped consistently
 * (the same policy the existing inline scan applies) so callers see a
 * deterministic synchronous result.
 *
 * Pure module — no `vscode` import — so it can be unit-tested without
 * the provider mock.
 */
export class ScanCache {
  private readonly entries = new Map<string, CachedToken[]>()

  getTokens(input: ScanCacheInputs): CachedToken[] {
    const key = this.keyFor(input.uriKey, input.version)
    const hit = this.entries.get(key)
    if (hit !== undefined) return hit

    // Evict any older versions of this URI before storing the new one
    // so we never accumulate more than one cached version per file.
    const prefix = input.uriKey + '@'
    for (const k of Array.from(this.entries.keys())) {
      if (k.startsWith(prefix)) this.entries.delete(k)
    }

    const computed = this.compute(input)
    this.entries.set(key, computed)
    return computed
  }

  /**
   * Drops every cached entry for `uriKey`. Called when a document is
   * closed or its tab disappears, so we don't keep analyzed tokens for
   * files the user can no longer see.
   */
  invalidate(uriKey: string): void {
    const prefix = uriKey + '@'
    for (const k of Array.from(this.entries.keys())) {
      if (k.startsWith(prefix)) this.entries.delete(k)
    }
  }

  clear(): void {
    this.entries.clear()
  }

  /** Number of cached `(uri, version)` slots — exposed for tests. */
  get size(): number {
    return this.entries.size
  }

  private keyFor(uriKey: string, version: number): string {
    return `${uriKey}@${version}`
  }

  private compute(input: ScanCacheInputs): CachedToken[] {
    let hits: ReturnType<typeof scanDocument>
    try {
      hits = scanDocument(input.text, input.registry)
    } catch {
      return []
    }
    const out: CachedToken[] = []
    for (const hit of hits) {
      const analyzer = input.registry.get(hit.analyzerId)
      if (!analyzer) continue
      const match: Match = {
        text: hit.text,
        range: { start: hit.startOffset, end: hit.endOffset },
      }
      try {
        const result = analyzer.analyze(match)
        // Async analyzers are intentionally skipped — the tree builder
        // is synchronous, and shipped analyzers are all sync today.
        if (result instanceof Promise) continue
        out.push({
          analyzerId: hit.analyzerId,
          analyzerName: hit.analyzerName,
          kind: result.kind ?? '',
          range: {
            startLine: hit.startLine,
            startColumn: hit.startColumn,
            endLine: hit.endLine,
            endColumn: hit.endColumn,
          },
          sections: result.sections ?? [],
          findings: result.findings ?? [],
        })
      } catch {
        // skip on analyze failure (matches existing behaviour)
      }
    }
    return out
  }
}
