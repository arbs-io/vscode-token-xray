import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  addOpenTab,
  FakeTabInputText,
  FakeUri,
  makeDoc,
  resetVscodeMock,
  vscodeMockState,
} from '../__test-utils__/vscodeMock'
import { TreeNodeDto } from '../core/findingsTree'
import {
  FindingsTreeViewProvider,
  registerFindingsTreeViewProvider,
} from './findingsTreeViewProvider'

// A minimal JWT (`alg=HS256`, payload `{"sub":"test"}`, dummy sig). The
// JWT analyzer's detector picks it up as a single token, which gives
// the tree exactly one root node we can count.
const SAMPLE_JWT =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dGVzdHNpZw'

interface FakeContext {
  subscriptions: Array<{ dispose: () => void }>
}

function makeContext(): FakeContext {
  return { subscriptions: [] }
}

function getProvider(): FindingsTreeViewProvider {
  const opts = vscodeMockState.lastTreeViewOptions as
    | { treeDataProvider: FindingsTreeViewProvider }
    | undefined
  if (!opts) throw new Error('Tree view was not registered')
  return opts.treeDataProvider
}

async function getRoots(provider: FindingsTreeViewProvider): Promise<TreeNodeDto[]> {
  return (await provider.getChildren()) as TreeNodeDto[]
}

beforeEach(() => {
  resetVscodeMock()
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('FindingsTreeViewProvider — scan filter', () => {
  it('excludes documents whose URI has no open tab (ghost docs)', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, SAMPLE_JWT))
    // No tab is registered, so the doc is a ghost.
    const provider = new FindingsTreeViewProvider()
    provider.refresh()
    expect(await getRoots(provider)).toEqual([])
  })

  it('includes documents that have a matching open tab', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, SAMPLE_JWT))
    addOpenTab(new FakeTabInputText(uri))
    const provider = new FindingsTreeViewProvider()
    provider.refresh()
    const roots = await getRoots(provider)
    expect(roots).toHaveLength(1)
    expect(roots[0].kind).toBe('tokenRoot')
    expect(roots[0].analyzerId).toBe('jwt')
  })

  it('drops tokens for a doc once its tab is removed and refresh re-runs', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, SAMPLE_JWT))
    addOpenTab(new FakeTabInputText(uri))
    const provider = new FindingsTreeViewProvider()
    provider.refresh()
    expect((await getRoots(provider))).toHaveLength(1)

    // Simulate tab closure: doc lingers in textDocuments but tab is gone.
    vscodeMockState.tabGroups.length = 0
    provider.refresh()
    expect(await getRoots(provider)).toEqual([])
  })
})

describe('registerFindingsTreeViewProvider — wiring', () => {
  it('runs an initial refresh synchronously on activation', async () => {
    const uri = FakeUri.file('/repo/x.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, SAMPLE_JWT))
    addOpenTab(new FakeTabInputText(uri))
    registerFindingsTreeViewProvider(makeContext() as never)
    expect(await getRoots(getProvider())).toHaveLength(1)
  })

  it('debounces a burst of events into a single refresh', () => {
    registerFindingsTreeViewProvider(makeContext() as never)
    const provider = getProvider()
    let fires = 0
    provider.onDidChangeTreeData(() => {
      fires++
    })

    vscodeMockState.openTextDocEmitter.fire({} as never)
    vscodeMockState.changeTextDocEmitter.fire({} as never)
    vscodeMockState.changeDiagnosticsEmitter.fire({ uris: [] })

    vi.advanceTimersByTime(49)
    expect(fires).toBe(0)
    vi.advanceTimersByTime(1)
    expect(fires).toBe(1)
  })

  it('refreshes when tabs are opened or closed', () => {
    registerFindingsTreeViewProvider(makeContext() as never)
    const provider = getProvider()
    let fires = 0
    provider.onDidChangeTreeData(() => {
      fires++
    })

    vscodeMockState.changeTabsEmitter.fire({
      opened: [{ label: 'a', input: undefined }],
      closed: [],
      changed: [],
    })
    vi.advanceTimersByTime(50)
    expect(fires).toBe(1)

    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [{ label: 'a', input: undefined }],
      changed: [],
    })
    vi.advanceTimersByTime(50)
    expect(fires).toBe(2)
  })

  it('does not refresh on tab change events that only carry `changed` (focus flips)', () => {
    registerFindingsTreeViewProvider(makeContext() as never)
    const provider = getProvider()
    let fires = 0
    provider.onDidChangeTreeData(() => {
      fires++
    })

    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [],
      changed: [{ label: 'a', input: undefined }],
    })
    vi.advanceTimersByTime(100)
    expect(fires).toBe(0)
  })

  it('renders per-analyzer icons + severity-coloured badges on token roots', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, SAMPLE_JWT))
    addOpenTab(new FakeTabInputText(uri))
    const provider = new FindingsTreeViewProvider()
    provider.refresh()
    const [root] = await getRoots(provider)
    expect(root.kind).toBe('tokenRoot')

    const item = provider.getTreeItem(root)
    // The JWT analyzer should map to the `key` codicon. The fake
    // ThemeIcon stores its id on `.id` and the colour on `.color`.
    expect((item.iconPath as { id: string }).id).toBe('key')
    // Description picks up the file location and (when present) a
    // compact severity badge: "leak.ts:1 · 1W" etc.
    expect(typeof item.description).toBe('string')
    expect(item.description as string).toContain('leak.ts')
  })

  it('uses a recognised section icon for known section titles', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, SAMPLE_JWT))
    addOpenTab(new FakeTabInputText(uri))
    const provider = new FindingsTreeViewProvider()
    provider.refresh()
    const [root] = await getRoots(provider)
    const groups = (root.children ?? []).filter((c) => c.kind === 'sectionGroup')
    const header = groups.find((g) => g.label.toLowerCase().includes('header'))
    const claims = groups.find((g) => g.label.toLowerCase().includes('claims'))
    expect(header).toBeDefined()
    expect(claims).toBeDefined()

    // "JOSE Header" matches the "jose" entry → symbol-namespace.
    expect((provider.getTreeItem(header!).iconPath as { id: string }).id).toBe(
      'symbol-namespace'
    )
    // "Claims" → symbol-property.
    expect((provider.getTreeItem(claims!).iconPath as { id: string }).id).toBe(
      'symbol-property'
    )
  })

  it('clears the pending debounced refresh on context disposal', () => {
    const ctx = makeContext()
    registerFindingsTreeViewProvider(ctx as never)
    const provider = getProvider()
    let fires = 0
    provider.onDidChangeTreeData(() => {
      fires++
    })

    vscodeMockState.openTextDocEmitter.fire({} as never)
    // Dispose every subscription registered by the provider — the
    // dispose handler clears the pending timer so the refresh never
    // fires even after the debounce interval elapses.
    for (const s of ctx.subscriptions) s.dispose()
    vi.advanceTimersByTime(100)
    expect(fires).toBe(0)
  })
})
