// Pure helper for `.ipynb` (Jupyter notebook) JSON documents.
//
// VS Code surfaces notebook cells as individual `TextDocument`s with scheme
// `vscode-notebook-cell` — when the existing diagnostics provider opts that
// scheme in, every cell flows through `scanText` exactly like an ordinary
// source file. That covers the live-editing case end-to-end and is the
// primary path the `notebook-cell-scanning` enhancement uses.
//
// This helper is a complementary path: it parses an `.ipynb` file's raw
// JSON body and returns each cell's source text. It's intentionally pure
// (no vscode imports) so future workspace-wide scans (CodeLens, batch
// analysis, CLI smoke tests, etc.) can read `.ipynb` files directly from
// disk without spinning up a notebook host.
//
// Scope:
//   * Tolerates the v4 schema where `source` may be either a single string
//     or an array of strings (`["line 1\n", "line 2"]`). When it's an array
//     we concatenate the segments verbatim — the v4 spec stores trailing
//     newlines on each segment so a plain join produces the original cell
//     body without inserting or stripping newlines.
//   * Accepts any of the three v4 cell kinds (`code`, `markdown`, `raw`).
//     Anything else falls through as `raw` so the caller never has to
//     guard on an unexpected literal.
//   * Returns `[]` for invalid JSON, missing `cells` array, non-array
//     `cells`, and any other shape the v4 schema rejects. The caller can
//     therefore treat the helper as a total function.

/** One entry per cell in `extractCellTexts`'s output. */
export interface NotebookCell {
  /** 0-based position of the cell in the notebook's `cells` array. */
  index: number
  /** v4 cell type — non-standard literals collapse to `'raw'`. */
  kind: 'code' | 'markdown' | 'raw'
  /** Concatenated cell text (array `source` is joined verbatim). */
  source: string
}

/**
 * Parse an `.ipynb` JSON body and return one entry per cell.
 *
 * Tolerates the v4 schema variants where `source` may be either a string
 * or an array of strings. Returns `[]` on any parse / shape failure so
 * the caller can pass the result straight to a text-scanning pipeline
 * without an extra try/catch.
 */
export function extractCellTexts(notebookJsonText: string): NotebookCell[] {
  if (!notebookJsonText) return []

  let parsed: unknown
  try {
    parsed = JSON.parse(notebookJsonText)
  } catch {
    // Malformed JSON: surface nothing rather than throwing. The provider
    // would otherwise have to wrap every call in try/catch.
    return []
  }

  if (!parsed || typeof parsed !== 'object') return []
  const cells = (parsed as { cells?: unknown }).cells
  if (!Array.isArray(cells)) return []

  const out: NotebookCell[] = []
  for (let i = 0; i < cells.length; i++) {
    const cell = cells[i]
    if (!cell || typeof cell !== 'object') continue
    const source = readSource((cell as { source?: unknown }).source)
    if (source === undefined) continue
    out.push({
      index: i,
      kind: readKind((cell as { cell_type?: unknown }).cell_type),
      source,
    })
  }
  return out
}

/**
 * Normalise the `cell_type` literal. Anything outside the v4 spec's
 * three values collapses to `'raw'` so the caller never has to guard.
 */
function readKind(value: unknown): NotebookCell['kind'] {
  if (value === 'code') return 'code'
  if (value === 'markdown') return 'markdown'
  return 'raw'
}

/**
 * Normalise the `source` field. v4 stores it as either:
 *   * a single string ("import os\nprint(1)"), or
 *   * an array of strings (["import os\n", "print(1)"]) where each
 *     element carries its own trailing newline.
 *
 * We return the concatenated body in both cases. Non-string array elements
 * are coerced via `String(...)` so a stray `null` / `number` doesn't blow
 * up the join — that matches Jupyter's "best effort" tolerance in practice.
 *
 * Returns `undefined` when `source` is missing or has a completely
 * unrecognised shape (e.g. a boolean), letting the caller skip the cell.
 */
function readSource(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) {
    let out = ''
    for (const piece of value) {
      out += typeof piece === 'string' ? piece : String(piece)
    }
    return out
  }
  return undefined
}
