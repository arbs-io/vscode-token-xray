import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  FakePosition,
  FakeUri,
  makeDoc,
  resetVscodeMock,
} from '../__test-utils__/vscodeMock'
import { GenericHoverProvider } from './hoverProvider'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
}

const JWT = `${b64u({ alg: 'HS256' })}.${b64u({ sub: 'alice' })}.dGVzdHNpZw`

beforeEach(() => {
  resetVscodeMock()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('GenericHoverProvider', () => {
  it('returns undefined for unsupported URI schemes', async () => {
    const provider = new GenericHoverProvider()
    const doc = makeDoc(
      new FakeUri({ scheme: 'vscode-notebook-cell', path: '/nb.ipynb' }),
      JWT
    )
    const result = await provider.provideHover(
      doc as never,
      new FakePosition(0, 5) as never,
      {} as never
    )
    expect(result).toBeUndefined()
  })

  it('returns undefined when the document is empty', async () => {
    const provider = new GenericHoverProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), '')
    const result = await provider.provideHover(
      doc as never,
      new FakePosition(0, 0) as never,
      {} as never
    )
    expect(result).toBeUndefined()
  })

  it('returns undefined when the cursor is outside every detected token', async () => {
    const provider = new GenericHoverProvider()
    // JWT at the end; cursor at the start of the prefix.
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), `noise   ${JWT}`)
    const result = await provider.provideHover(
      doc as never,
      new FakePosition(0, 2) as never,
      {} as never
    )
    expect(result).toBeUndefined()
  })

  it('returns a Hover when the cursor is inside a detected token', async () => {
    const provider = new GenericHoverProvider()
    const doc = makeDoc(FakeUri.file('/repo/a.ts'), JWT)
    const result = await provider.provideHover(
      doc as never,
      new FakePosition(0, 5) as never,
      {} as never
    )
    expect(result).toBeDefined()
    // The Hover constructor stores its `contents` argument unchanged.
    expect((result as unknown as { contents: { value: string } }).contents.value)
      .toMatch(/JWT|JWS|HS256|alice/)
  })

  it('returns undefined when the document is over the configured size cap', async () => {
    const provider = new GenericHoverProvider()
    // 2 MiB of plain text — twice the default cap of 1 MiB.
    const doc = makeDoc(FakeUri.file('/repo/big.ts'), 'a'.repeat(2 * 1024 * 1024))
    const result = await provider.provideHover(
      doc as never,
      new FakePosition(0, 0) as never,
      {} as never
    )
    expect(result).toBeUndefined()
  })
})
