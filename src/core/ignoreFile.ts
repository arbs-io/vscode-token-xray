// Pure helper for `.tokenxrayignore` files. No vscode imports.
//
// Honors `.gitignore`-style syntax for path-level suppression of all
// Token X-Ray findings (not just secrets). The actual glob matching is
// delegated to `matchesGlob` in `globMatch.ts` so behaviour stays in
// lock-step with the existing `tokenXray.secrets.exclude` setting.
//
// Semantics:
//   * Lines beginning with `#` are comments (skipped).
//   * Blank / whitespace-only lines are skipped.
//   * Trailing whitespace on each line is trimmed.
//   * A leading `!` negates a previously matched pattern (un-ignore).
//   * Last matching rule wins — exactly how `.gitignore` resolves
//     conflicts between an ignore line and a later `!negation`.

import { matchesGlob } from './globMatch'

/**
 * Strip comments + blank lines from a `.tokenxrayignore` file body and
 * return the active pattern list. Order is preserved so callers can feed
 * the result straight to `matchIgnore`.
 *
 * Patterns themselves are not normalised here — the leading `!` for
 * negations is kept intact and consumed later by `matchIgnore`. This
 * mirrors how Git stores the entries it reads from `.gitignore`.
 */
export function parseIgnoreFile(text: string): string[] {
  if (!text) return []

  const out: string[] = []
  // `.gitignore` line endings are LF on Linux and CRLF on Windows; we
  // tolerate either by splitting on '\n' and stripping any trailing '\r'.
  const lines = text.split('\n')
  for (const line of lines) {
    // Trim trailing whitespace (including a trailing `\r` from CRLF
    // files); `.gitignore` treats trailing whitespace as significant
    // only when escaped with a backslash, which we don't honour here.
    const trimmed = line.replace(/[\t \r]+$/, '')
    if (trimmed.length === 0) continue
    // Leading whitespace is significant for `.gitignore`; we follow
    // suit and only skip lines whose *entire* content is whitespace
    // (handled by the trim above leaving "").
    if (trimmed[0] === '#') continue
    out.push(trimmed)
  }
  return out
}

/**
 * Returns `true` when `relPath` should be excluded according to the
 * supplied `.gitignore`-style pattern list.
 *
 * The decision is made by walking the patterns in order and remembering
 * the latest match: a plain pattern flips the verdict to "ignored", a
 * `!negation` flips it back to "not ignored". The final verdict is
 * returned; patterns that don't match the path don't change anything.
 *
 * This is the semantics Git uses — see `gitignore(5)`'s wording about
 * "the last matching pattern decides the outcome".
 *
 * `relPath` should already be relative to the workspace root. Empty
 * pattern lists, nullish inputs, and empty paths all return `false`.
 */
export function matchIgnore(relPath: string, patterns: readonly string[]): boolean {
  if (!relPath) return false
  if (!patterns || patterns.length === 0) return false

  let ignored = false
  for (const pattern of patterns) {
    if (!pattern) continue
    if (pattern[0] === '!') {
      const body = pattern.slice(1)
      if (!body) continue
      if (matchesGlob(relPath, body)) {
        ignored = false
      }
    } else {
      if (matchesGlob(relPath, pattern)) {
        ignored = true
      }
    }
  }
  return ignored
}
