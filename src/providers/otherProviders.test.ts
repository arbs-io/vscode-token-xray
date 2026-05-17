// Smoke tests for the lower-risk providers — each one's pure logic
// already lives in `src/core/` and is tested there. These tests cover
// the thin vscode adapter layer: supported-scheme filtering, empty-text
// short-circuits, and registration disposable plumbing.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  FakePosition,
  FakeRange,
  FakeUri,
  makeDoc,
  resetVscodeMock,
} from '../__test-utils__/vscodeMock'
import { SecurityCodeLensProvider, registerSecurityCodeLensProvider } from './securityCodeLensProvider'
import { SecurityDocumentLinksProvider, registerDocumentLinksProvider } from './documentLinksProvider'
import { SecurityDocumentSymbolsProvider, registerDocumentSymbolsProvider } from './documentSymbolsProvider'
import { SecurityInlayHintsProvider, registerInlayHintsProvider } from './inlayHintsProvider'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
}

const JWT = `${b64u({ alg: 'HS256' })}.${b64u({ sub: 'a' })}.dGVzdHNpZw`

interface FakeCtx {
  subscriptions: Array<{ dispose: () => void }>
}
function makeCtx(): FakeCtx {
  return { subscriptions: [] }
}

beforeEach(() => {
  resetVscodeMock()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('SecurityCodeLensProvider', () => {
  it('returns no lenses for unsupported schemes', () => {
    const provider = new SecurityCodeLensProvider()
    const doc = makeDoc(new FakeUri({ scheme: 'vscode-notebook-cell', path: '/nb.ipynb' }), JWT)
    expect(provider.provideCodeLenses(doc as never, {} as never)).toEqual([])
  })

  it('emits one CodeLens per detected token', () => {
    const provider = new SecurityCodeLensProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), JWT)
    const lenses = provider.provideCodeLenses(doc as never, {} as never)
    expect(lenses).toHaveLength(1)
    expect((lenses[0] as { command?: { command: string } }).command?.command).toBe(
      'tokenXray.inspect'
    )
  })

  it('register hooks supply at least one disposable', () => {
    const ctx = makeCtx()
    registerSecurityCodeLensProvider(ctx as never)
    expect(ctx.subscriptions.length).toBeGreaterThan(0)
  })
})

describe('SecurityDocumentLinksProvider', () => {
  it('returns [] for unsupported schemes', async () => {
    const provider = new SecurityDocumentLinksProvider()
    const doc = makeDoc(new FakeUri({ scheme: 'vscode-notebook-cell', path: '/nb.ipynb' }), JWT)
    expect(await provider.provideDocumentLinks(doc as never, {} as never)).toEqual([])
  })

  it('returns [] for an empty document', async () => {
    const provider = new SecurityDocumentLinksProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), '')
    expect(await provider.provideDocumentLinks(doc as never, {} as never)).toEqual([])
  })

  it('does not throw when no tokens are present', async () => {
    const provider = new SecurityDocumentLinksProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), 'plain prose, no tokens here')
    const links = await provider.provideDocumentLinks(doc as never, {} as never)
    expect(Array.isArray(links)).toBe(true)
  })

  it('register hooks supply at least one disposable', () => {
    const ctx = makeCtx()
    registerDocumentLinksProvider(ctx as never)
    expect(ctx.subscriptions.length).toBeGreaterThan(0)
  })
})

describe('SecurityDocumentSymbolsProvider', () => {
  it('returns [] for unsupported schemes', async () => {
    const provider = new SecurityDocumentSymbolsProvider()
    const doc = makeDoc(new FakeUri({ scheme: 'vscode-notebook-cell', path: '/nb.ipynb' }), JWT)
    expect(await provider.provideDocumentSymbols(doc as never, {} as never)).toEqual([])
  })

  it('returns [] for an empty document', async () => {
    const provider = new SecurityDocumentSymbolsProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), '')
    expect(await provider.provideDocumentSymbols(doc as never, {} as never)).toEqual([])
  })

  it('emits at least one symbol for a JWT-bearing document', async () => {
    const provider = new SecurityDocumentSymbolsProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), JWT)
    const symbols = await provider.provideDocumentSymbols(doc as never, {} as never)
    expect(symbols.length).toBeGreaterThan(0)
  })

  it('register hooks supply at least one disposable', () => {
    const ctx = makeCtx()
    registerDocumentSymbolsProvider(ctx as never)
    expect(ctx.subscriptions.length).toBeGreaterThan(0)
  })
})

describe('SecurityInlayHintsProvider', () => {
  it('returns [] for unsupported schemes', async () => {
    const provider = new SecurityInlayHintsProvider()
    const doc = makeDoc(new FakeUri({ scheme: 'vscode-notebook-cell', path: '/nb.ipynb' }), JWT)
    const range = new FakeRange(0, 0, 0, JWT.length)
    expect(await provider.provideInlayHints(doc as never, range as never, {} as never)).toEqual([])
  })

  it('returns [] for an empty document', async () => {
    const provider = new SecurityInlayHintsProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), '')
    const range = new FakeRange(0, 0, 0, 0)
    expect(await provider.provideInlayHints(doc as never, range as never, {} as never)).toEqual([])
  })

  it('range.start/end use Position-like shape', async () => {
    // Sanity: the offsetAt path used by inlay hints accepts FakePosition.
    const provider = new SecurityInlayHintsProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), JWT)
    const range = {
      start: new FakePosition(0, 0),
      end: new FakePosition(0, JWT.length),
    }
    const hints = await provider.provideInlayHints(doc as never, range as never, {} as never)
    expect(Array.isArray(hints)).toBe(true)
  })

  it('register hooks supply at least one disposable', () => {
    const ctx = makeCtx()
    registerInlayHintsProvider(ctx as never)
    expect(ctx.subscriptions.length).toBeGreaterThan(0)
  })
})

describe('registerStatusBarBadgeProvider', () => {
  it('registers without throwing and creates at least one disposable', async () => {
    const ctx = makeCtx()
    const { registerStatusBarBadgeProvider } = await import('./statusBarBadgeProvider')
    registerStatusBarBadgeProvider(ctx as never)
    expect(ctx.subscriptions.length).toBeGreaterThan(0)
  })
})
