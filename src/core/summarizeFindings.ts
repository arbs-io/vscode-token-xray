import { Finding } from './types'

/**
 * Per-severity counts derived from a list of findings, plus the
 * pre-rendered status-bar label and a `hidden` flag the adapter uses to
 * decide whether to show or hide the `StatusBarItem`.
 *
 * The label encodes only the categories with at least one entry, so a
 * document with two errors and no warnings produces `$(shield) 2 errors`
 * rather than `$(shield) 2 errors, 0 warnings`. Info findings are noisy
 * by design — they are only included in the label when there are no
 * errors or warnings, otherwise the badge would over-amplify low-signal
 * informational hits.
 */
export interface FindingSummary {
  errors: number
  warnings: number
  infos: number
  /**
   * Human-readable label suitable for `vscode.StatusBarItem.text`. The
   * leading `$(shield)` is a VS Code icon glyph reference; it renders as
   * a small shield icon next to the text.
   *
   * Returns an empty string when `hidden` is true so the adapter can
   * unconditionally write to `StatusBarItem.text` without leaving a
   * stale value behind.
   */
  label: string
  /**
   * True when the summary has no findings (all three counters are zero).
   * The provider adapter calls `StatusBarItem.hide()` in this case.
   */
  hidden: boolean
}

/**
 * Pure mapper from finding list → status-bar summary.
 *
 * Label rules (per the backlog spec):
 *   - Drop zero-count categories from the label entirely.
 *   - When there are errors or warnings, suppress the `info` count from
 *     the label even when it is non-zero — info findings stay countable
 *     via tooltip / Problems panel but should not crowd the status bar.
 *   - Pluralize each category independently: `1 error`, `2 errors`,
 *     `1 warning`, `2 warnings`. The `info` category collapses to a
 *     single noun (`1 info`, `2 infos`) — short and unambiguous.
 *   - Always prefix the label with `$(shield)` so the badge reads as a
 *     security indicator at a glance.
 *
 * Hidden rule:
 *   - All three counts zero → `hidden: true`, label is the empty string.
 *
 * The function never throws and never reads from anything but the
 * provided findings list — no vscode imports.
 */
export function summarizeFindings(
  findings: readonly Finding[] | undefined | null
): FindingSummary {
  let errors = 0
  let warnings = 0
  let infos = 0

  if (findings) {
    for (const finding of findings) {
      if (!finding) continue
      switch (finding.severity) {
        case 'error':
          errors++
          break
        case 'warning':
          warnings++
          break
        case 'info':
          infos++
          break
      }
    }
  }

  if (errors === 0 && warnings === 0 && infos === 0) {
    return { errors: 0, warnings: 0, infos: 0, label: '', hidden: true }
  }

  const parts: string[] = []
  if (errors > 0) parts.push(pluralize(errors, 'error', 'errors'))
  if (warnings > 0) parts.push(pluralize(warnings, 'warning', 'warnings'))
  // `info` only appears in the label when it is the sole category. As
  // soon as errors / warnings show up, info collapses into the tooltip
  // so the badge stays focused on the highest-severity signal.
  if (errors === 0 && warnings === 0 && infos > 0) {
    parts.push(pluralize(infos, 'info', 'infos'))
  }

  const label = `$(shield) ${parts.join(', ')}`

  return { errors, warnings, infos, label, hidden: false }
}

function pluralize(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`
}
