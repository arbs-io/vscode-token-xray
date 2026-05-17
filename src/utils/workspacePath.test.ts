import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  FakeUri,
  makeDoc,
  resetVscodeMock,
  vscodeMockState,
} from '../__test-utils__/vscodeMock'
import {
  effectiveUri,
  fallbackDisplayLabel,
  notebookFileUri,
  workspaceRelativeFilename,
  workspaceRelativePathForIgnore,
} from './workspacePath'

beforeEach(() => {
  resetVscodeMock()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('notebookFileUri', () => {
  it('returns the parent .ipynb URI for a notebook cell', () => {
    const cell = new FakeUri({
      scheme: 'vscode-notebook-cell',
      path: '/repo/notebook.ipynb',
      fragment: 'cell-1',
    })
    const parent = notebookFileUri(cell)
    expect(parent?.scheme).toBe('file')
    expect(parent?.path).toBe('/repo/notebook.ipynb')
    expect(parent?.fragment).toBe('')
  })

  it('returns undefined for non-cell schemes', () => {
    expect(notebookFileUri(FakeUri.file('/x'))).toBeUndefined()
    expect(notebookFileUri(new FakeUri({ scheme: 'untitled', path: 'a' }))).toBeUndefined()
  })

  it('returns undefined for cell URIs missing a path', () => {
    expect(notebookFileUri(new FakeUri({ scheme: 'vscode-notebook-cell', path: '' }))).toBeUndefined()
  })
})

describe('effectiveUri', () => {
  it('returns the parent URI for a notebook cell document', () => {
    const cell = new FakeUri({
      scheme: 'vscode-notebook-cell',
      path: '/repo/notebook.ipynb',
      fragment: 'cell-1',
    })
    expect(effectiveUri(makeDoc(cell, '')).scheme).toBe('file')
  })

  it('returns the document URI unchanged for ordinary files', () => {
    const uri = FakeUri.file('/repo/a.ts')
    expect(effectiveUri(makeDoc(uri, '')).toString()).toBe(uri.toString())
  })
})

describe('workspaceRelativeFilename', () => {
  it('strips the workspace prefix and leading separators', () => {
    vscodeMockState.workspaceFolders.push({
      uri: FakeUri.file('/repo'),
      name: 'repo',
      index: 0,
    })
    const doc = makeDoc(FakeUri.file('/repo/src/auth.ts'), '')
    expect(workspaceRelativeFilename(doc)).toBe('src/auth.ts')
  })

  it('falls back to fsPath when the file is outside every workspace folder', () => {
    vscodeMockState.workspaceFolders.push({
      uri: FakeUri.file('/repo'),
      name: 'repo',
      index: 0,
    })
    const doc = makeDoc(FakeUri.file('/elsewhere/x.ts'), '')
    expect(workspaceRelativeFilename(doc)).toBe('/elsewhere/x.ts')
  })

  it('returns undefined for untitled buffers', () => {
    const doc = makeDoc(new FakeUri({ scheme: 'untitled', path: 'Untitled-1' }), '')
    expect(workspaceRelativeFilename(doc)).toBeUndefined()
  })

  it('resolves notebook cells to the parent .ipynb path', () => {
    vscodeMockState.workspaceFolders.push({
      uri: FakeUri.file('/repo'),
      name: 'repo',
      index: 0,
    })
    const doc = makeDoc(
      new FakeUri({
        scheme: 'vscode-notebook-cell',
        path: '/repo/nb.ipynb',
        fragment: 'cell-1',
      }),
      ''
    )
    expect(workspaceRelativeFilename(doc)).toBe('nb.ipynb')
  })
})

describe('workspaceRelativePathForIgnore', () => {
  it('normalises path separators to forward slashes', () => {
    const folder = { uri: FakeUri.file('/repo'), name: 'repo', index: 0 }
    vscodeMockState.workspaceFolders.push(folder)
    const doc = makeDoc(FakeUri.file('/repo/src/auth.ts'), '')
    expect(workspaceRelativePathForIgnore(doc, folder)).toBe('src/auth.ts')
  })

  it('returns undefined when the document is outside the folder', () => {
    const folder = { uri: FakeUri.file('/repo'), name: 'repo', index: 0 }
    const doc = makeDoc(FakeUri.file('/elsewhere/x.ts'), '')
    expect(workspaceRelativePathForIgnore(doc, folder)).toBeUndefined()
  })
})

describe('fallbackDisplayLabel', () => {
  it('returns the URI basename', () => {
    expect(fallbackDisplayLabel(FakeUri.file('/repo/a/b/c.ts'))).toBe('c.ts')
  })

  it('falls back to the URI string when there is no path', () => {
    const uri = new FakeUri({ scheme: 'about', path: '' })
    expect(fallbackDisplayLabel(uri)).toBe(uri.toString())
  })
})
