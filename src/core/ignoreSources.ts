// Multi-source `.gitignore` / `.tokenxrayignore` matcher.
//
// The workspace can hold many ignore files: a root `.gitignore`, a root
// `.tokenxrayignore`, plus nested `.gitignore` files in subdirectories
// (e.g. `dist/.gitignore`, `coverage/.gitignore`). Each one's patterns
// are interpreted relative to the file's own directory. This module
// holds the pure matcher; the vscode-aware loader (in
// `securityDiagnosticsProvider`) feeds it the discovered sources.
//
// Semantics:
//   * Sources are processed in walk order (outer → inner). Each source
//     is evaluated only against the portion of the file path that sits
//     inside that source's `baseDir`.
//   * Within a source, the existing `.gitignore` "last matching rule
//     wins" rule applies via `matchIgnore`.
//   * Across sources, the most-specific (deepest baseDir) source's
//     verdict overrides outer sources — matching how `git` treats a
//     subdirectory `.gitignore` as authoritative over its parent.
//
// No vscode imports — pure JS, unit-testable in isolation.

import { matchesGlob } from './globMatch'

export interface IgnoreSource {
  /**
   * Absolute fsPath of the directory the patterns are relative to.
   * Always normalised to forward slashes for cross-platform matching.
   */
  baseDir: string
  /** Patterns parsed from the file (leading `!` negations preserved). */
  patterns: string[]
}

type SourceVerdict = 'ignored' | 'negated' | 'unmatched'

/**
 * Run one source's patterns against a path that already sits inside
 * the source's `baseDir`. Returns the tristate verdict so the caller
 * can decide cross-source precedence.
 *
 * Mirrors `matchIgnore`'s last-matching-rule-wins semantics but
 * preserves the "no rule matched" answer that the boolean form drops.
 */
function evaluateSource(relPath: string, patterns: readonly string[]): SourceVerdict {
  let verdict: SourceVerdict = 'unmatched'
  for (const pattern of patterns) {
    if (!pattern) continue
    if (pattern.startsWith('!')) {
      const body = pattern.slice(1)
      if (body && matchesGlob(relPath, body)) verdict = 'negated'
    } else if (matchesGlob(relPath, pattern)) {
      verdict = 'ignored'
    }
  }
  return verdict
}

function relativeTo(filePath: string, baseDir: string): string | undefined {
  if (!filePath.startsWith(baseDir)) return undefined
  const rel = filePath.slice(baseDir.length).replace(/^[\\/]+/, '').replace(/\\/g, '/')
  return rel.length > 0 ? rel : undefined
}

/**
 * Returns true when `filePath` should be excluded according to the
 * supplied ignore sources.
 *
 * `filePath` must be an absolute fsPath. Sources are evaluated from
 * shallowest baseDir to deepest, and the deepest source that matched
 * (positive OR negation) decides the outcome — matching `git`'s
 * behaviour where a subdirectory's `.gitignore` is authoritative over
 * its parent's. Sources whose `baseDir` is not an ancestor of
 * `filePath` are skipped.
 */
export function isIgnoredByAnySource(
  filePath: string,
  sources: readonly IgnoreSource[]
): boolean {
  if (!filePath || sources.length === 0) return false
  const ordered = [...sources].sort((a, b) => a.baseDir.length - b.baseDir.length)
  let ignored = false
  for (const source of ordered) {
    const rel = relativeTo(filePath, source.baseDir)
    if (rel === undefined) continue
    const verdict = evaluateSource(rel, source.patterns)
    if (verdict === 'ignored') ignored = true
    else if (verdict === 'negated') ignored = false
    // unmatched: leave previous verdict unchanged.
  }
  return ignored
}
