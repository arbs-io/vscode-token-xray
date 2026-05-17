import { describe, expect, it } from 'vitest'
import { samlResponseFixture } from '../analyzers/saml/fixtures'
import { createDefaultRegistry } from './defaultRegistry'
import { diagnosticsAcrossRegistry, findingToDiagnostic } from './diagnostics'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
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

  it('honours `tokenxray-disable-next-line` for the line directly below', async () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const text = `// tokenxray-disable-next-line jwt.alg.none\n${token}`
    const out = await diagnosticsAcrossRegistry(text, reg)
    expect(out.every((d) => d.code !== 'jwt.alg.none')).toBe(true)
  })

  it('honours `tokenxray-disable-file` across the document', async () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const text = `// tokenxray-disable-file jwt.alg.none\nfiller\n${token}`
    const out = await diagnosticsAcrossRegistry(text, reg)
    expect(out.every((d) => d.code !== 'jwt.alg.none')).toBe(true)
  })

  it('keeps unrelated findings on a line that suppresses one rule', async () => {
    // A document with two analyzers firing on the same target line —
    // only one is silenced, the other should still surface. The custom
    // analyzers anchor their range on a fixed `target` substring so the
    // computed startLine matches the line the directive points at.
    const reg2 = createDefaultRegistry()
    const target = 'target-marker'
    const detect = (t: string) => {
      const idx = t.indexOf(target)
      return idx < 0 ? [] : [{ text: target, range: { start: idx, end: idx + target.length } }]
    }
    reg2.register({
      id: 'first',
      name: 'first',
      detect,
      analyze: () => ({
        analyzerId: 'first',
        kind: 'demo',
        sections: [],
        findings: [{ id: 'first.flagged', severity: 'warning' as const, message: 'flagged' }],
      }),
    })
    reg2.register({
      id: 'second',
      name: 'second',
      detect,
      analyze: () => ({
        analyzerId: 'second',
        kind: 'demo',
        sections: [],
        findings: [{ id: 'second.kept', severity: 'warning' as const, message: 'kept' }],
      }),
    })
    const text = `// tokenxray-disable-next-line first.flagged\n${target}\n`
    const out = await diagnosticsAcrossRegistry(text, reg2)
    expect(out.some((d) => d.code === 'second.kept')).toBe(true)
    expect(out.every((d) => d.code !== 'first.flagged')).toBe(true)
  })

  it('drops findings whose id maps to `off` via ruleSeverity', async () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const out = await diagnosticsAcrossRegistry(token, reg, {
      ruleSeverity: { 'jwt.alg.none': 'off' },
    })
    expect(out.every((d) => d.code !== 'jwt.alg.none')).toBe(true)
  })

  it('rewrites severity via ruleSeverity', async () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const out = await diagnosticsAcrossRegistry(token, reg, {
      ruleSeverity: { 'jwt.alg.none': 'warning' },
    })
    const algNone = out.find((d) => d.code === 'jwt.alg.none')
    expect(algNone?.severity).toBe('warning')
  })

  it('honours `off` via ruleSeverity even when no inline directive is present', async () => {
    // Same fixture as the disable-comment test, but with no comment in
    // the document — ruleSeverity should still drop the finding.
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const text = `code goes here\n${token}\n`
    const out = await diagnosticsAcrossRegistry(text, reg, {
      ruleSeverity: { 'jwt.alg.none': 'off' },
    })
    expect(out.every((d) => d.code !== 'jwt.alg.none')).toBe(true)
  })

  it('returns [] when ruleSeverity drops every finding', async () => {
    // Single analyzer, single finding, hard-suppressed via wildcard.
    const reg2 = createDefaultRegistry()
    reg2.register({
      id: 'lonely',
      name: 'lonely',
      detect: (t) => (t.length > 0 ? [{ text: t, range: { start: 0, end: t.length } }] : []),
      analyze: () => ({
        analyzerId: 'lonely',
        kind: 'demo',
        sections: [],
        findings: [{ id: 'lonely.warn', severity: 'warning' as const, message: 'w' }],
      }),
    })
    const out = await diagnosticsAcrossRegistry('hello', reg2, {
      ruleSeverity: { 'lonely.*': 'off' },
    })
    expect(out).toEqual([])
  })

  it('preserves duplicate findings that happen to share id + line + message', async () => {
    // Two analyzer registrations emit the same finding shape on the
    // same line. The dedup-aware filter must not collapse them.
    const reg2 = createDefaultRegistry()
    for (const id of ['twinA', 'twinB'] as const) {
      reg2.register({
        id,
        name: id,
        detect: (t) => (t.length > 0 ? [{ text: t, range: { start: 0, end: t.length } }] : []),
        analyze: () => ({
          analyzerId: id,
          kind: 'demo',
          sections: [],
          findings: [{ id: 'demo.shared', severity: 'warning' as const, message: 'shared' }],
        }),
      })
    }
    const out = await diagnosticsAcrossRegistry('plain text body', reg2)
    const sources = out.filter((d) => d.code === 'demo.shared').map((d) => d.source).sort()
    expect(sources).toEqual(['twinA', 'twinB'])
  })
})
