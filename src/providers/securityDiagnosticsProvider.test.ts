import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

// `scanText` is mocked so each test can control whether the scan
// resolves immediately, hangs (so we can race a tab-close against it),
// or returns canned diagnostics. The hoisted handle lets the factory
// reference a mock declared later in the file.
const { scanTextMock } = vi.hoisted(() => ({ scanTextMock: vi.fn() }))
vi.mock('../core/scanText', () => ({
  scanText: scanTextMock,
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES: 1048576,
}))

// `debugOutputChannel` pulls in the `vscode.window.createOutputChannel`
// API we haven't stubbed, so we short-circuit it to a no-op logger.
vi.mock('./debugOutputChannel', () => ({
  getDebugLogger: () => () => undefined,
  registerDebugOutputChannel: () => undefined,
}))

import {
  addOpenTab,
  FakeDiagnosticCollection,
  FakeTabInputText,
  FakeUri,
  makeDoc,
  resetVscodeMock,
  vscodeMockState,
} from '../__test-utils__/vscodeMock'
import type { DiagnosticDto } from '../core/diagnostics'
import { registerSecurityDiagnosticsProvider } from './securityDiagnosticsProvider'

interface FakeContext {
  subscriptions: Array<{ dispose: () => void }>
}

function makeContext(): FakeContext {
  return { subscriptions: [] }
}

function getCollection(): FakeDiagnosticCollection {
  const c = vscodeMockState.diagnosticCollections.find((x) => x.name === 'tokenXray')
  if (!c) throw new Error('tokenXray diagnostic collection was never created')
  return c
}

function makeDto(code = 'jwt.alg.none'): DiagnosticDto {
  return {
    message: 'finding',
    severity: 'warning',
    source: 'tokenXray',
    code,
    range: { startLine: 0, startColumn: 0, endLine: 0, endColumn: 10 },
  }
}

/**
 * Returns a `[promise, resolve]` pair so a test can await one tick to
 * let the provider call `scanText`, take action (e.g. close the tab),
 * then resolve the scan and inspect what got published.
 */
function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

beforeEach(() => {
  resetVscodeMock()
  scanTextMock.mockReset()
  scanTextMock.mockResolvedValue([])
})

afterEach(() => {
  vi.useRealTimers()
})

describe('refresh — basic publishing', () => {
  it('publishes diagnostics for an open document with a matching tab', async () => {
    const uri = FakeUri.file('/repo/secrets.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'irrelevant'))
    addOpenTab(new FakeTabInputText(uri))
    scanTextMock.mockResolvedValueOnce([makeDto()])

    registerSecurityDiagnosticsProvider(makeContext() as never)
    // refresh is fired off as `void refresh(doc)` from registration;
    // wait for it to settle.
    await new Promise((r) => setImmediate(r))

    expect(getCollection().get(uri)).toHaveLength(1)
  })

  it('clears the URI on onDidCloseTextDocument', async () => {
    const uri = FakeUri.file('/repo/secrets.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    scanTextMock.mockResolvedValueOnce([makeDto()])

    registerSecurityDiagnosticsProvider(makeContext() as never)
    await new Promise((r) => setImmediate(r))
    expect(getCollection().has(uri)).toBe(true)

    vscodeMockState.closeTextDocEmitter.fire(makeDoc(uri, 'x'))
    expect(getCollection().has(uri)).toBe(false)
  })
})

describe('refresh — scan cancellation', () => {
  it('drops a stale scan whose tab closed mid-scan', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    const d = deferred<DiagnosticDto[]>()
    scanTextMock.mockReturnValueOnce(d.promise)

    registerSecurityDiagnosticsProvider(makeContext() as never)
    // Let the scan start.
    await Promise.resolve()

    // Simulate user closing the tab while the scan is in flight.
    vscodeMockState.tabGroups.length = 0
    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [{ label: 'leak', input: undefined }],
      changed: [],
    })

    // Now resolve the in-flight scan — its results must NOT be published
    // because the URI's token was invalidated by the tab-close handler.
    d.resolve([makeDto()])
    await new Promise((r) => setImmediate(r))

    expect(getCollection().has(uri)).toBe(false)
  })

  it('drops a stale scan when a newer refresh supersedes it', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    const first = deferred<DiagnosticDto[]>()
    const second = deferred<DiagnosticDto[]>()
    scanTextMock.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)

    // Disable change debouncing so the synthetic change event flushes
    // synchronously — production uses a 250ms trailing edge that this
    // test isn't exercising.
    registerSecurityDiagnosticsProvider(makeContext() as never, { changeDebounceMs: 0 })
    await Promise.resolve()

    // Fire a change to trigger a second refresh while the first is in
    // flight. The second scan claims a newer token, invalidating the
    // first.
    vscodeMockState.changeTextDocEmitter.fire({ document: makeDoc(uri, 'y') })
    await Promise.resolve()

    // Resolve the first scan with a "stale" result first. The provider
    // must drop it because the second scan now owns the latest token.
    first.resolve([makeDto('jwt.stale')])
    await new Promise((r) => setImmediate(r))
    expect(getCollection().get(uri) ?? []).toHaveLength(0)

    // Resolve the second scan with the canonical result; this one wins.
    second.resolve([makeDto('jwt.fresh')])
    await new Promise((r) => setImmediate(r))
    expect(getCollection().get(uri)?.[0].code).toBe('jwt.fresh')
  })
})

describe('refresh — change debounce', () => {
  it('coalesces a burst of change events into a single scan on the trailing edge', async () => {
    vi.useFakeTimers()
    const uri = FakeUri.file('/repo/typing.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    scanTextMock.mockResolvedValue([])

    registerSecurityDiagnosticsProvider(makeContext() as never, { changeDebounceMs: 250 })
    // Open-time scan runs immediately — drain pending microtasks so we
    // observe a clean baseline before firing the burst.
    await vi.advanceTimersByTimeAsync(0)
    const baseline = scanTextMock.mock.calls.length

    for (let i = 0; i < 5; i++) {
      vscodeMockState.changeTextDocEmitter.fire({ document: makeDoc(uri, `y${i}`) })
      await vi.advanceTimersByTimeAsync(50)
    }
    // Halfway through the debounce window — still no extra scan.
    expect(scanTextMock.mock.calls.length).toBe(baseline)

    await vi.advanceTimersByTimeAsync(250)
    expect(scanTextMock.mock.calls.length).toBe(baseline + 1)
  })

  it('cancels a pending debounced scan when the tab closes', async () => {
    vi.useFakeTimers()
    const uri = FakeUri.file('/repo/typing.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    scanTextMock.mockResolvedValue([])

    registerSecurityDiagnosticsProvider(makeContext() as never, { changeDebounceMs: 250 })
    await vi.advanceTimersByTimeAsync(0)
    const baseline = scanTextMock.mock.calls.length

    vscodeMockState.changeTextDocEmitter.fire({ document: makeDoc(uri, 'y') })

    // Tab closes before the debounce fires; pending scan must be canceled.
    vscodeMockState.tabGroups.length = 0
    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [{ label: 'typing', input: undefined }],
      changed: [],
    })

    await vi.advanceTimersByTimeAsync(500)
    expect(scanTextMock.mock.calls.length).toBe(baseline)
  })
})

describe('tab close cleanup', () => {
  it('removes diagnostics for URIs whose tab closed without an onDidCloseTextDocument event', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    scanTextMock.mockResolvedValueOnce([makeDto()])
    registerSecurityDiagnosticsProvider(makeContext() as never)
    await new Promise((r) => setImmediate(r))
    expect(getCollection().has(uri)).toBe(true)

    // Mimic VS Code: the tab is gone but the doc is still in textDocuments
    // and no close event ever fires. The tab-listener should still
    // reconcile and clear the collection.
    vscodeMockState.tabGroups.length = 0
    vscodeMockState.changeTabsEmitter.fire({
      opened: [],
      closed: [{ label: 'leak', input: undefined }],
      changed: [],
    })

    expect(getCollection().has(uri)).toBe(false)
  })

  it('ignores tab change events that carry no closed tabs', async () => {
    const uri = FakeUri.file('/repo/leak.ts')
    vscodeMockState.textDocuments.push(makeDoc(uri, 'x'))
    addOpenTab(new FakeTabInputText(uri))
    scanTextMock.mockResolvedValueOnce([makeDto()])
    registerSecurityDiagnosticsProvider(makeContext() as never)
    await new Promise((r) => setImmediate(r))

    vscodeMockState.changeTabsEmitter.fire({
      opened: [{ label: 'other', input: undefined }],
      closed: [],
      changed: [],
    })

    // Diagnostics for the still-open tab survive.
    expect(getCollection().has(uri)).toBe(true)
  })
})
