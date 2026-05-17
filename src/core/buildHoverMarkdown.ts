import { AnalysisResult, Finding, Section, SectionRow } from './types'

/**
 * Severity → emoji indicator used in the hover findings bullet list. Kept
 * inline (rather than a lookup table consumed by other modules) because the
 * hover markdown is the only surface that uses these icons today, and the
 * mapping is stable enough that callers reach for the symbols directly when
 * eyeballing test output.
 */
const SEVERITY_ICON: Record<Finding['severity'], string> = {
  error: '🔴',
  warning: '🟠',
  info: '🔵',
}

/**
 * Pure hover renderer. Takes an `AnalysisResult` from any analyzer and
 * returns a self-contained Markdown string suitable for a vscode hover
 * card (the provider adapter wraps the return value in `MarkdownString`).
 *
 * No vscode imports here — the function is fully unit-testable as plain
 * string transformation and reused by `src/providers/hoverProvider.ts`.
 *
 * The shape:
 *   - Header line `**<ANALYZER_ID>** — <kind>`
 *   - One `### <title>` per section, followed by a 2-column Markdown
 *     table of `Key | Value` rows (description appended in parens when
 *     present).
 *   - Findings block (only when `result.findings` is non-empty) as a
 *     bullet list, each bullet prefixed with the severity emoji.
 *
 * Empty sections and empty findings are handled gracefully (the
 * corresponding block is omitted).
 */
export function buildHoverMarkdown(result: AnalysisResult): string {
  const lines: string[] = []
  lines.push(headerLine(result))

  for (const section of result.sections) {
    const block = renderSection(section)
    if (block) {
      lines.push('', block)
    }
  }

  if (result.findings.length > 0) {
    lines.push('', '### Findings')
    for (const finding of result.findings) {
      lines.push(renderFinding(finding))
    }
  }

  return lines.join('\n')
}

function headerLine(result: AnalysisResult): string {
  const id = (result.analyzerId ?? '').toUpperCase()
  const kind = result.kind ?? 'detection'
  return `**${id}** — ${kind}`
}

function renderSection(section: Section): string | undefined {
  if (!section.rows || section.rows.length === 0) {
    // Still emit the heading so callers can see an empty section was
    // detected — but skip the table to avoid producing a stray
    // `| --- |` separator without content.
    return `### ${section.title}`
  }
  const lines: string[] = [`### ${section.title}`, '| Key | Value |', '| --- | --- |']
  for (const row of section.rows) {
    lines.push(renderRow(row))
  }
  return lines.join('\n')
}

function renderRow(row: SectionRow): string {
  const key = escapeCell(row.key)
  const value = formatValue(row.value)
  const cell = row.description ? `${value} _(${escapeCell(row.description)})_` : value
  return `| ${key} | ${cell} |`
}

function renderFinding(finding: Finding): string {
  const icon = SEVERITY_ICON[finding.severity] ?? '⚫'
  const id = finding.id ? `\`${finding.id}\`` : ''
  const docLink = finding.docUrl ? ` [docs](${finding.docUrl})` : ''
  const parts = [icon, id, '—', escapeInline(finding.message)].filter((p) => p !== '')
  return `- ${parts.join(' ')}${docLink}`
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '_(none)_'
  if (typeof value === 'string') return escapeCell(value)
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) return escapeCell(value.map(String).join(', '))
  try {
    return '`' + JSON.stringify(value) + '`'
  } catch {
    return escapeCell('[unserializable value]')
  }
}

/**
 * Escape characters that would otherwise break a Markdown table cell.
 * vscode renders hover Markdown with the standard GFM table parser, so
 * a literal `|` in a value would split the cell. Newlines are folded
 * to `<br>` so multi-line values render as a single visual cell.
 */
function escapeCell(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, String.raw`\|`)
    .replace(/\r?\n/g, '<br>')
}

/**
 * Escape inline Markdown text where a stray backtick or pipe would
 * render oddly inside a bullet list. We intentionally do NOT escape
 * `*` or `_` here because finding messages occasionally contain shell
 * snippets where those characters are load-bearing.
 */
function escapeInline(value: string): string {
  return value.replace(/\r?\n/g, ' ')
}
