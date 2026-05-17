import { describe, expect, it } from 'vitest'
import { extractCellTexts } from './notebookScan'

/**
 * Minimal v4-shaped `.ipynb` fixture used across the positive-path
 * tests. Carries one code cell with a string-form `source` and one
 * markdown cell with an array-form `source` so a single fixture
 * exercises both concatenation branches.
 */
const NOTEBOOK_FIXTURE = JSON.stringify({
  cells: [
    {
      cell_type: 'code',
      execution_count: 1,
      metadata: {},
      outputs: [],
      source: "import os\nprint(os.environ['SECRET'])\n",
    },
    {
      cell_type: 'markdown',
      metadata: {},
      source: ['# Heading\n', '\n', 'Some **markdown** text.\n'],
    },
  ],
  metadata: { kernelspec: { name: 'python3' } },
  nbformat: 4,
  nbformat_minor: 5,
})

describe('extractCellTexts', () => {
  it('parses a minimal v4 ipynb with code and markdown cells', () => {
    const cells = extractCellTexts(NOTEBOOK_FIXTURE)
    expect(cells).toHaveLength(2)
    expect(cells[0]).toEqual({
      index: 0,
      kind: 'code',
      source: "import os\nprint(os.environ['SECRET'])\n",
    })
    expect(cells[1]).toEqual({
      index: 1,
      kind: 'markdown',
      source: '# Heading\n\nSome **markdown** text.\n',
    })
  })

  it('concatenates array-form source verbatim (preserves embedded newlines)', () => {
    // Each array element carries its own trailing newline per the v4 spec;
    // a plain join reproduces the original cell body without inserting or
    // stripping newlines.
    const text = JSON.stringify({
      cells: [
        { cell_type: 'code', source: ['line 1\n', 'line 2\n', 'line 3'] },
      ],
    })
    expect(extractCellTexts(text)[0].source).toBe('line 1\nline 2\nline 3')
  })

  it('handles string-form source without modification', () => {
    const text = JSON.stringify({
      cells: [{ cell_type: 'code', source: 'a = 1\nb = 2' }],
    })
    expect(extractCellTexts(text)[0].source).toBe('a = 1\nb = 2')
  })

  it('treats raw cell_type as raw', () => {
    const text = JSON.stringify({
      cells: [{ cell_type: 'raw', source: 'literal' }],
    })
    expect(extractCellTexts(text)[0].kind).toBe('raw')
  })

  it('collapses unknown cell_type to raw', () => {
    // Future v5 / extension-added kinds should fall through cleanly
    // rather than panicking the caller.
    const text = JSON.stringify({
      cells: [{ cell_type: 'foo', source: 'x' }],
    })
    expect(extractCellTexts(text)[0].kind).toBe('raw')
  })

  it('coerces non-string elements inside an array source', () => {
    // Best-effort tolerance — Jupyter itself accepts a stray non-string
    // element via String() in the wild, so we mirror that behaviour.
    const text = JSON.stringify({
      cells: [{ cell_type: 'code', source: ['x = ', 1, '\n'] }],
    })
    expect(extractCellTexts(text)[0].source).toBe('x = 1\n')
  })

  it('skips cells that are missing source entirely', () => {
    const text = JSON.stringify({
      cells: [
        { cell_type: 'code' },
        { cell_type: 'code', source: 'keep' },
      ],
    })
    const cells = extractCellTexts(text)
    expect(cells).toHaveLength(1)
    // Index reflects the original position even though cell 0 was dropped.
    expect(cells[0]).toEqual({ index: 1, kind: 'code', source: 'keep' })
  })

  it('skips cells whose source is an unsupported shape', () => {
    // Booleans / numbers / objects aren't valid v4 source values.
    const text = JSON.stringify({
      cells: [
        { cell_type: 'code', source: true },
        { cell_type: 'code', source: 42 },
        { cell_type: 'code', source: { foo: 'bar' } },
        { cell_type: 'code', source: null },
      ],
    })
    expect(extractCellTexts(text)).toEqual([])
  })

  it('skips falsy / non-object cell entries inside cells[]', () => {
    const text = JSON.stringify({
      cells: [null, 0, false, 'string-cell', { cell_type: 'code', source: 'k' }],
    })
    const cells = extractCellTexts(text)
    expect(cells).toHaveLength(1)
    expect(cells[0].index).toBe(4)
  })

  it('returns [] on invalid JSON', () => {
    expect(extractCellTexts('{not json}')).toEqual([])
    expect(extractCellTexts('null')).toEqual([])
    expect(extractCellTexts('"a string"')).toEqual([])
    expect(extractCellTexts('42')).toEqual([])
  })

  it('returns [] when cells field is missing or not an array', () => {
    expect(extractCellTexts(JSON.stringify({}))).toEqual([])
    expect(extractCellTexts(JSON.stringify({ cells: 'oops' }))).toEqual([])
    expect(extractCellTexts(JSON.stringify({ cells: 123 }))).toEqual([])
    expect(extractCellTexts(JSON.stringify({ cells: null }))).toEqual([])
  })

  it('returns [] for the empty string', () => {
    expect(extractCellTexts('')).toEqual([])
  })

  it('returns [] when cells[] is empty', () => {
    expect(extractCellTexts(JSON.stringify({ cells: [] }))).toEqual([])
  })

  it('assigns 0-based indices to each cell', () => {
    const text = JSON.stringify({
      cells: [
        { cell_type: 'code', source: 'a' },
        { cell_type: 'markdown', source: 'b' },
        { cell_type: 'code', source: 'c' },
      ],
    })
    expect(extractCellTexts(text).map((c) => c.index)).toEqual([0, 1, 2])
  })
})
