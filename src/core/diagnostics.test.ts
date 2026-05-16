import { describe, expect, it } from 'vitest'
import { samlResponseFixture } from '../analyzers/saml/fixtures'
import { createDefaultRegistry } from './defaultRegistry'
import { diagnosticsAcrossRegistry, findingToDiagnostic } from './diagnostics'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

describe('findingToDiagnostic', () => {
  it('maps severities', () => {
    const r = { startLine: 0, startColumn: 0, endLine: 0, endColumn: 1 }
    expect(findingToDiagnostic({ id: 'x', severity: 'error', message: 'm' }, 'src', r).severity).toBe(
      'error'
    )
    expect(findingToDiagnostic({ id: 'x', severity: 'warning', message: 'm' }, 'src', r).severity).toBe(
      'warning'
    )
    expect(findingToDiagnostic({ id: 'x', severity: 'info', message: 'm' }, 'src', r).severity).toBe(
      'information'
    )
  })
})

describe('diagnosticsAcrossRegistry', () => {
  const reg = createDefaultRegistry()

  it('emits no diagnostics for inert text', async () => {
    expect(await diagnosticsAcrossRegistry('hello world', reg)).toEqual([])
  })

  it('emits jwt diagnostics for an alg:none token', async () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const out = await diagnosticsAcrossRegistry(token, reg)
    expect(out.some((d) => d.code === 'jwt.alg.none' && d.severity === 'error')).toBe(true)
  })

  it('emits saml diagnostics for an unsigned response', async () => {
    const xml = samlResponseFixture({ signed: false })
    const out = await diagnosticsAcrossRegistry(xml, reg)
    expect(out.some((d) => d.code === 'saml.signature.missing')).toBe(true)
    expect(out.find((d) => d.code === 'saml.signature.missing')?.source).toBe('saml')
  })

  it('returns empty for empty input', async () => {
    expect(await diagnosticsAcrossRegistry('', reg)).toEqual([])
  })

  it('skips analyzers whose analyze throws', async () => {
    const reg2 = createDefaultRegistry()
    reg2.register({
      id: 'flaky',
      name: 'flaky',
      detect: (t) => [{ text: t, range: { start: 0, end: t.length } }],
      analyze: () => {
        throw new Error('nope')
      },
    })
    const out = await diagnosticsAcrossRegistry('anything', reg2)
    expect(out.every((d) => d.source !== 'flaky')).toBe(true)
  })

  it('uses a line range when match has no range', async () => {
    const reg2 = createDefaultRegistry()
    reg2.register({
      id: 'rangeless',
      name: 'rangeless',
      detect: (t) => (t.length > 0 ? [{ text: t }] : []),
      analyze: () => ({
        analyzerId: 'rangeless',
        kind: 'demo',
        sections: [],
        findings: [{ id: 'demo.x', severity: 'warning' as const, message: 'x' }],
      }),
    })
    const out = await diagnosticsAcrossRegistry('hello', reg2)
    const hit = out.find((d) => d.source === 'rangeless')
    expect(hit?.range.startLine).toBe(0)
  })
})
