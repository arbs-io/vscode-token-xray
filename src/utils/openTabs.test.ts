import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  addOpenTab,
  FakeTabInputNotebook,
  FakeTabInputNotebookDiff,
  FakeTabInputText,
  FakeTabInputTextDiff,
  FakeUri,
  resetVscodeMock,
} from '../__test-utils__/vscodeMock'
import { effectiveTabUri, openTabUriStrings } from './openTabs'

beforeEach(() => {
  resetVscodeMock()
})

describe('openTabUriStrings', () => {
  it('returns an empty set when there are no tabs', () => {
    expect(openTabUriStrings()).toEqual(new Set())
  })

  it('collects URIs from text tabs', () => {
    const uri = FakeUri.file('/repo/src/main.ts')
    addOpenTab(new FakeTabInputText(uri))
    expect(openTabUriStrings()).toEqual(new Set([uri.toString()]))
  })

  it('collects notebook tab URIs', () => {
    const uri = FakeUri.file('/notebooks/leak.ipynb')
    addOpenTab(new FakeTabInputNotebook(uri))
    expect(openTabUriStrings().has(uri.toString())).toBe(true)
  })

  it('captures both sides of a text diff tab', () => {
    const original = FakeUri.file('/repo/a.ts')
    const modified = FakeUri.file('/repo/b.ts')
    addOpenTab(new FakeTabInputTextDiff(original, modified))
    const set = openTabUriStrings()
    expect(set.has(original.toString())).toBe(true)
    expect(set.has(modified.toString())).toBe(true)
  })

  it('captures both sides of a notebook diff tab', () => {
    const original = FakeUri.file('/notebooks/a.ipynb')
    const modified = FakeUri.file('/notebooks/b.ipynb')
    addOpenTab(new FakeTabInputNotebookDiff(original, modified))
    const set = openTabUriStrings()
    expect(set.has(original.toString())).toBe(true)
    expect(set.has(modified.toString())).toBe(true)
  })

  it('ignores tabs with unknown input types (webview, terminal, custom)', () => {
    addOpenTab({ kind: 'webview' })
    addOpenTab(undefined)
    expect(openTabUriStrings()).toEqual(new Set())
  })
})

describe('effectiveTabUri', () => {
  it('returns file URI unchanged', () => {
    const uri = FakeUri.file('/repo/x.ts')
    expect(effectiveTabUri(uri as never)).toBe(uri)
  })

  it('maps notebook cell URIs to their parent .ipynb file URI', () => {
    const cell = new FakeUri({
      scheme: 'vscode-notebook-cell',
      path: '/notebooks/leak.ipynb',
      fragment: 'cell-3',
    })
    const result = effectiveTabUri(cell as never)
    expect(result.scheme).toBe('file')
    expect(result.path).toBe('/notebooks/leak.ipynb')
    expect(result.fragment).toBe('')
  })

  it('returns input unchanged when notebook cell URI has no path', () => {
    const cell = new FakeUri({ scheme: 'vscode-notebook-cell', path: '' })
    expect(effectiveTabUri(cell as never)).toBe(cell)
  })
})
