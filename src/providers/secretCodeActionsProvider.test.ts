import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vscode', async () => {
  const mock = await import('../__test-utils__/vscodeMock')
  return mock.vscodeMockModule
})

import {
  FakeDiagnostic,
  FakeRange,
  FakeUri,
  FakeWorkspaceEdit,
  makeDoc,
  resetVscodeMock,
  vscodeMockState,
} from '../__test-utils__/vscodeMock'
import { SecretCodeActionsProvider } from './secretCodeActionsProvider'

interface FakeCodeActionContext {
  diagnostics: FakeDiagnostic[]
  only?: unknown
  triggerKind?: number
}

/** Build a `vscode.Diagnostic`-shaped value with the fields the provider reads. */
function makeDiagnostic(opts: {
  code: string
  source: string
  message?: string
  range?: FakeRange
  severity?: number
}): FakeDiagnostic {
  const range = opts.range ?? new FakeRange(0, 0, 0, 10)
  const d = new FakeDiagnostic(range, opts.message ?? 'finding', opts.severity ?? 1)
  d.code = opts.code
  d.source = opts.source
  return d
}

beforeEach(() => {
  resetVscodeMock()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('SecretCodeActionsProvider', () => {
  it('returns no actions for unsupported URI schemes', () => {
    const provider = new SecretCodeActionsProvider()
    const doc = makeDoc(
      new FakeUri({ scheme: 'vscode-notebook-cell', path: '/nb.ipynb' }),
      'AKIAIOSFODNN7EXAMPLE'
    )
    const ctx: FakeCodeActionContext = {
      diagnostics: [makeDiagnostic({ code: 'secret.aws.accessKey', source: 'secret' })],
    }
    const result = provider.provideCodeActions(
      doc as never,
      new FakeRange(0, 0, 0, 0) as never,
      ctx as never,
      {} as never
    )
    expect(result).toEqual([])
  })

  it('ignores diagnostics whose source is not the secret analyzer', () => {
    const provider = new SecretCodeActionsProvider()
    const doc = makeDoc(FakeUri.file('/repo/leak.ts'), 'eyJhbGciOiJIUzI1NiJ9.abc.def')
    const ctx: FakeCodeActionContext = {
      diagnostics: [
        // JWT diagnostic — should be skipped even with a secret-shaped code.
        makeDiagnostic({ code: 'jwt.alg.none', source: 'tokenXray' }),
      ],
    }
    const result = provider.provideCodeActions(
      doc as never,
      new FakeRange(0, 0, 0, 0) as never,
      ctx as never,
      {} as never
    )
    expect(result).toEqual([])
  })

  it('emits Redact + Move-to-.env.example actions for a secret diagnostic', () => {
    const provider = new SecretCodeActionsProvider()
    // Document body must include the matched span — the pure mapper reads it
    // to derive matching-length redaction text.
    const text = 'AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n'
    const doc = makeDoc(FakeUri.file('/repo/leak.ts'), text)
    const range = new FakeRange(0, 22, 0, 42) // covers AKIA…EXAMPLE
    const diag = makeDiagnostic({
      code: 'secret.aws.accessKey',
      source: 'secret',
      range,
      message: 'AWS access key',
    })
    const ctx: FakeCodeActionContext = { diagnostics: [diag] }

    const actions = provider.provideCodeActions(
      doc as never,
      range as never,
      ctx as never,
      {} as never
    )
    expect(actions.length).toBeGreaterThanOrEqual(1)
    for (const action of actions) {
      expect(action.title).toBeTruthy()
      expect(action.edit).toBeInstanceOf(FakeWorkspaceEdit)
      // Every action should be linked back to the originating diagnostic so
      // the lightbulb anchors to the right squiggle.
      expect(action.diagnostics).toEqual([diag])
    }
  })

  it('returns no actions when the diagnostics list is empty', () => {
    const provider = new SecretCodeActionsProvider()
    const doc = makeDoc(FakeUri.file('/repo/leak.ts'), 'noop')
    const result = provider.provideCodeActions(
      doc as never,
      new FakeRange(0, 0, 0, 0) as never,
      { diagnostics: [] } as never,
      {} as never
    )
    expect(result).toEqual([])
  })

  it('skips diagnostics whose code does not have the secret prefix', () => {
    const provider = new SecretCodeActionsProvider()
    const doc = makeDoc(FakeUri.file('/repo/leak.ts'), 'x')
    const ctx: FakeCodeActionContext = {
      diagnostics: [
        // Source is "secret" but code namespace is wrong — must be skipped
        // so the redact filter can't accidentally rewrite non-secret hits.
        makeDiagnostic({ code: 'jwt.alg.none', source: 'secret' }),
      ],
    }
    const result = provider.provideCodeActions(
      doc as never,
      new FakeRange(0, 0, 0, 0) as never,
      ctx as never,
      {} as never
    )
    expect(result).toEqual([])
  })

  it('respects the secrets.codeActions.enabled=false setting at registration time', async () => {
    vscodeMockState.configSlices.set('tokenXray', { 'secrets.codeActions.enabled': false })
    const { registerSecretCodeActionsProvider } = await import('./secretCodeActionsProvider')
    const ctx = { subscriptions: [] as Array<{ dispose: () => void }> }
    registerSecretCodeActionsProvider(ctx as never)
    // No code-action provider registration disposable was pushed because
    // the setting short-circuited the function.
    expect(ctx.subscriptions).toEqual([])
  })
})
