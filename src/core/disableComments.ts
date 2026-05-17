import { Finding } from './types'

/**
 * A finding paired with the (zero-based) line at which it surfaces in the
 * source document. The `applyDisableComments` filter uses `startLine` to
 * match a finding against any `tokenxray-disable-next-line` markers that
 * sit on a comment immediately above the finding.
 *
 * The shape is intentionally minimal — providers may carry their existing
 * range structures separately; only `startLine` is consulted here.
 */
export type FindingWithLocation = Finding & { startLine: number }

interface DisableNextLineRule {
  /** Line index of the *next non-blank line* the directive should silence. */
  targetLine: number
  /** Rule ids (or `prefix.*` wildcards) listed on the directive. */
  ruleIds: string[]
}

interface FileScopeRule {
  /** Rule ids (or `prefix.*` wildcards) listed on the directive. */
  ruleIds: string[]
}

interface ParsedDirectives {
  nextLine: DisableNextLineRule[]
  file: FileScopeRule[]
}

/**
 * Match a comment line starting with optional whitespace, then either
 * `//` or `#`, then a single space, then the directive verb + the rest of
 * the comment.
 *
 * Captures:
 *   [1] = verb (`tokenxray-disable-next-line` | `tokenxray-disable-file`)
 *   [2] = remainder of the line (everything after the verb)
 */
const DIRECTIVE_RE =
  /^[\t ]*(?:\/\/|#)[\t ]*(tokenxray-disable-next-line|tokenxray-disable-file)\b([^\r\n]*)$/

/**
 * Pure filter: drops findings whose `id` matches a rule listed on a
 * `tokenxray-disable-next-line` directive on the comment line directly
 * above the finding (skipping blank lines), or on any
 * `tokenxray-disable-file` directive anywhere in the document.
 *
 * Rule id matching is exact, or prefix-match when the listed value ends
 * in `.*` (e.g. `secret.*` matches all `secret.something` ids).
 *
 * Both `//` and `#` comment styles are honoured so this works for TS / JS
 * / Python / shell / TOML / YAML buffers alike.
 *
 * The function is pure: it never mutates the input array, never throws,
 * and never reads from anything but the supplied `findings` + `text`.
 * No vscode imports here.
 */
export function applyDisableComments(
  findings: FindingWithLocation[],
  text: string
): FindingWithLocation[] {
  if (!findings || findings.length === 0) return findings ?? []
  if (!text) return findings.slice()

  const directives = parseDirectives(text)
  if (directives.nextLine.length === 0 && directives.file.length === 0) {
    return findings.slice()
  }

  return findings.filter((finding) => !isDisabled(finding, directives))
}

/**
 * Walk the source text once and collect every `tokenxray-disable-next-line`
 * and `tokenxray-disable-file` directive. For next-line directives the
 * function resolves the *target line* — the next non-blank line — so
 * `isDisabled` can do an O(1) line-equality check per finding.
 */
function parseDirectives(text: string): ParsedDirectives {
  const lines = text.split('\n')
  const nextLine: DisableNextLineRule[] = []
  const file: FileScopeRule[] = []

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/\r$/, '')
    const m = DIRECTIVE_RE.exec(raw)
    if (!m) continue
    const verb = m[1]
    const ruleIds = parseRuleIds(m[2])
    if (ruleIds.length === 0) continue

    if (verb === 'tokenxray-disable-file') {
      file.push({ ruleIds })
      continue
    }
    // tokenxray-disable-next-line: skip blank lines to find the target.
    const target = findNextNonBlank(lines, i + 1)
    if (target === undefined) continue
    nextLine.push({ targetLine: target, ruleIds })
  }

  return { nextLine, file }
}

/**
 * Parse the rest-of-comment string into a list of rule ids.
 *
 *   ` foo.bar`              → [`foo.bar`]
 *   ` foo.bar, baz.qux`     → [`foo.bar`, `baz.qux`]
 *   ` foo.* , bar.*`        → [`foo.*`, `bar.*`]
 *   ` -- explanation`       → [] (no ids → directive is a no-op)
 *
 * Anything after a `#` (line comment within a `//` directive) or after
 * `--` is treated as a trailing remark and ignored.
 */
function parseRuleIds(rest: string): string[] {
  let trimmed = rest.trim()
  if (!trimmed) return []

  // Strip a `--` trailing remark so `// tokenxray-disable-next-line foo -- why`
  // still parses cleanly.
  const dashDash = trimmed.indexOf('--')
  if (dashDash >= 0) trimmed = trimmed.slice(0, dashDash).trim()
  if (!trimmed) return []

  return trimmed
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function findNextNonBlank(lines: string[], from: number): number | undefined {
  for (let i = from; i < lines.length; i++) {
    if (lines[i].trim().length > 0) return i
  }
  return undefined
}

function isDisabled(finding: FindingWithLocation, directives: ParsedDirectives): boolean {
  for (const rule of directives.file) {
    if (matchesAny(finding.id, rule.ruleIds)) return true
  }
  for (const rule of directives.nextLine) {
    if (rule.targetLine !== finding.startLine) continue
    if (matchesAny(finding.id, rule.ruleIds)) return true
  }
  return false
}

function matchesAny(findingId: string, ruleIds: string[]): boolean {
  for (const ruleId of ruleIds) {
    if (matches(findingId, ruleId)) return true
  }
  return false
}

function matches(findingId: string, ruleId: string): boolean {
  if (ruleId === findingId) return true
  if (ruleId.endsWith('.*')) {
    const prefix = ruleId.slice(0, -2)
    if (!prefix) return false
    if (findingId === prefix) return true
    return findingId.startsWith(prefix + '.')
  }
  return false
}
