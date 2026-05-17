import { DiagnosticDto, DiagnosticRangeDto } from './diagnostics'

/**
 * A single text edit produced by a code action. Coordinates are 0-based and
 * match `DiagnosticRangeDto` (the same shape used elsewhere in the pure layer).
 */
export interface CodeActionEditDto {
  range: DiagnosticRangeDto
  newText: string
}

/**
 * Side-effect describing work the vscode adapter must perform in addition to
 * applying `edits` (e.g. appending a line to `.env.example`). The pure mapper
 * only describes the intent; the adapter resolves paths and writes files.
 */
export interface CodeActionSideEffectDto {
  /** Currently only `appendToFile` is supported. */
  kind: 'appendToFile'
  /** Workspace-relative path of the file to append to. */
  file: string
  /** The line content to append (no trailing newline — the adapter manages that). */
  line: string
}

/**
 * Pure description of a quick-fix code action. The adapter in
 * `src/providers/secretCodeActionsProvider.ts` converts each DTO to a
 * `vscode.CodeAction` + `WorkspaceEdit`.
 */
export interface CodeActionDto {
  title: string
  kind: 'quickfix'
  edits: CodeActionEditDto[]
  sideEffects?: CodeActionSideEffectDto[]
  /** The diagnostic code (e.g. `secret.privateKey.pem`) this action fixes. */
  findingId: string
}

/** The placeholder string written in place of a secret when the user picks "Move to .env.example". */
export const REDACT_PLACEHOLDER = '<REDACTED>'

/** The default filename used for the "Move to .env.example" side-effect. */
export const DEFAULT_ENV_EXAMPLE_FILE = '.env.example'

/**
 * Returns `true` when `dto` is a secret-source diagnostic that we should
 * surface quick-fixes for. Exposed for tests and the adapter.
 *
 * We match on `code` starts with `secret.` — every built-in secret rule id
 * uses that namespace (see `src/analyzers/secrets/rules.ts`). The diagnostic
 * `source` is the analyzer id (`secret`), which we also check to avoid
 * surfacing fixes for diagnostics with the same code shape but a different
 * source.
 */
export function isSecretDiagnostic(dto: DiagnosticDto): boolean {
  return dto.source === 'secret' && dto.code.startsWith('secret.')
}

/**
 * Pure mapper: produce `CodeActionDto`s for the supplied diagnostics. Only
 * secret-source diagnostics (see `isSecretDiagnostic`) produce actions; all
 * others are ignored. Each qualifying diagnostic emits **two** actions:
 *
 *  - **Redact** — replace the diagnostic range with matching-length asterisks
 *    (minimum 3). The number of asterisks matches the sensitive span length so
 *    the document layout is preserved.
 *  - **Move to .env.example** — replace the secret value with `<REDACTED>`
 *    and ask the adapter to append a matching `KEY=<REDACTED>` line to
 *    `.env.example`. The key is derived from the surrounding text (an
 *    `KEY=value` / `KEY: value` / `"KEY": "value"` style label); if no key is
 *    found we fall back to `SECRET_<rule>` so the action still does something
 *    sensible.
 *
 * Diagnostics whose range is degenerate (zero-length) are skipped.
 *
 * @param diagnostics  The diagnostics to consider.
 * @param text         The full document text — used to derive env keys and to
 *                     resolve character offsets from line/column positions.
 * @param uri          The document uri (unused by the mapper itself but kept
 *                     in the signature so the adapter can pass the URI through
 *                     consistently; this also matches the spec in the backlog).
 */
export function findingsToCodeActionDtos(
  diagnostics: readonly DiagnosticDto[],
  text: string,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  uri?: string
): CodeActionDto[] {
  const out: CodeActionDto[] = []
  if (!diagnostics || diagnostics.length === 0) return out

  const lineStarts = computeLineStarts(text)

  for (const dto of diagnostics) {
    if (!isSecretDiagnostic(dto)) continue
    const startOffset = offsetFor(dto.range.startLine, dto.range.startColumn, lineStarts, text.length)
    const endOffset = offsetFor(dto.range.endLine, dto.range.endColumn, lineStarts, text.length)
    if (startOffset === undefined || endOffset === undefined) continue
    if (endOffset <= startOffset) continue

    // Redact: replace span with matching-length asterisks (min 3 so very short
    // matches stay visibly redacted).
    const span = endOffset - startOffset
    const asterisks = '*'.repeat(Math.max(span, 3))
    out.push({
      title: 'Redact secret',
      kind: 'quickfix',
      edits: [{ range: dto.range, newText: asterisks }],
      findingId: dto.code,
    })

    // Move to .env.example: replace secret with `<REDACTED>` and append a line
    // to `.env.example`. The env-key is derived from the surrounding text.
    const envKey = deriveEnvKey(text, startOffset, dto.code)
    out.push({
      title: `Move to ${DEFAULT_ENV_EXAMPLE_FILE}`,
      kind: 'quickfix',
      edits: [{ range: dto.range, newText: REDACT_PLACEHOLDER }],
      sideEffects: [
        {
          kind: 'appendToFile',
          file: DEFAULT_ENV_EXAMPLE_FILE,
          line: `${envKey}=${REDACT_PLACEHOLDER}`,
        },
      ],
      findingId: dto.code,
    })
  }

  return out
}

/**
 * Derive an environment-variable name to use in the `.env.example` line. We
 * look for a label immediately preceding the secret span:
 *
 *   - `KEY=value`            (dotenv style)
 *   - `KEY: value`           (yaml / config style)
 *   - `"KEY": "value"`       (json style)
 *   - `export KEY=value`     (shell)
 *
 * If no label is found, fall back to a name derived from the rule id (e.g.
 * `secret.aws.accessKey` → `SECRET_AWS_ACCESS_KEY`).
 */
function deriveEnvKey(text: string, secretStart: number, ruleId: string): string {
  // Look back at most 256 chars for a label. `KEY` must be a valid identifier
  // (uppercase/underscores/digits) — that's the standard env-var shape and
  // matches the patterns the secret rules already key off of.
  const lookBack = text.slice(Math.max(0, secretStart - 256), secretStart)
  // Match the rightmost label.
  const labelMatch = lookBack.match(/(?:["'])?([A-Z][A-Z0-9_]{1,63})(?:["'])?\s*[:=]\s*["']?$/)
  if (labelMatch) return labelMatch[1]
  return ruleIdToEnvKey(ruleId)
}

/** Convert `secret.aws.accessKey` → `SECRET_AWS_ACCESS_KEY`. */
function ruleIdToEnvKey(ruleId: string): string {
  return ruleId
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .toUpperCase()
}

/** Convert a (line, column) pair into a character offset. */
function offsetFor(line: number, column: number, lineStarts: number[], textLen: number): number | undefined {
  if (line < 0 || column < 0) return undefined
  if (line >= lineStarts.length) return undefined
  const offset = lineStarts[line] + column
  if (offset > textLen) return undefined
  return offset
}

function computeLineStarts(text: string): number[] {
  const starts = [0]
  for (let i = 0; i < text.length; i++) {
    if (text.codePointAt(i) === 10) starts.push(i + 1)
  }
  return starts
}
