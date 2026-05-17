import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  addOpenTab,
  FakeTabInputNotebook,
  FakeTabInputText,
  FakeUri,
  makeDoc,
  resetVscodeMock,
  vscodeMockState,
} from '../__test-utils__/vscodeMock'
import { ScanCache } from '../core/scanCache'
import { registerScanCacheLifecycle } from './scanCacheLifecycle'

interface FakeContext {
  subscriptions: Array<{ dispose: () => void }>
}

function makeContext(): FakeContext {
  return { subscriptions: [] }
}

beforeEach(() => {
  resetVscodeMock()
})

describe('registerScanCacheLifecycle', () => {
  it('invalidates the cache when a doc closes', () => {
    const cache = new ScanCache()
    const spy = vi.spyOn(cache, 'invalidate')
    registerScanCacheLifecycle(makeContext() as never, cache)

    const uri = FakeUri.file('/repo/x.ts')
    vscodeMockState.closeTextDocEmitter.fire(makeDoc(uri, 'x'))

    expect(spy).toHaveBeenCalledWith(uri.toString())
  })

  it('ignores tab events that have no closed tabs', () => {
    const cache = new ScanCache()
    const spy = vi.spyOn(cache, 'invalidate')
    registerScanCacheLifecycle(makeContext() as never, cache)

    vscodeMockState.changeTabsEmitter.fire({
      opened: [{ label: 'a', input: undefined }],
      closed: [],
      changed: [],
    })

    expect(spy).not.toHaveBeenCalled()
  })

  it('invalidates entries for docs whose tab has disappeared', () => {
    const cache = new ScanCache()
    const spy = vi.spyOn(cache, 'invalidate')
    registerScanCacheLifecycle(makeContext() as never, cache)

    const orphanUri = FakeUri.file('/repo/closed.ts')
    const visibleUri = FakeUri.file('/repo/open.ts')
    vscodeMockState.textDocuments.push(makeDoc(orphanUri, 'x'), makeDoc(visibleUri, 'y'))
    addOpenTab(new FakeTabInputText(visibleUri))

    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [{ label: 'closed.ts', input: undefined }],
      changed: [],
    })

    expect(spy).toHaveBeenCalledWith(orphanUri.toString())
    expect(spy).not.toHaveBeenCalledWith(visibleUri.toString())
  })

  it('invalidates notebook cells whose parent notebook tab is gone', () => {
    const cache = new ScanCache()
    const spy = vi.spyOn(cache, 'invalidate')
    registerScanCacheLifecycle(makeContext() as never, cache)

    // The orphaned notebook cell doc: its parent .ipynb has no tab.
    const cellUri = new FakeUri({
      scheme: 'vscode-notebook-cell',
      path: '/notebooks/leak.ipynb',
      fragment: 'cell-1',
    })
    // A visible notebook whose cell should survive the close event.
    const visibleNotebookUri = FakeUri.file('/notebooks/open.ipynb')
    const visibleCellUri = new FakeUri({
      scheme: 'vscode-notebook-cell',
      path: '/notebooks/open.ipynb',
      fragment: 'cell-1',
    })
    vscodeMockState.textDocuments.push(
      makeDoc(cellUri as never, 'x'),
      makeDoc(visibleCellUri as never, 'y')
    )
    addOpenTab(new FakeTabInputNotebook(visibleNotebookUri))

    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [{ label: 'leak.ipynb', input: undefined }],
      changed: [],
    })

    expect(spy).toHaveBeenCalledWith(cellUri.toString())
    expect(spy).not.toHaveBeenCalledWith(visibleCellUri.toString())
  })
})
