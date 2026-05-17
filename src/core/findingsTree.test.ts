import { describe, expect, it } from 'vitest'
import {
  buildTokenTree,
  buildTree,
  FindingTreeRange,
  SEVERITY_RANK_TABLE,
  TreeNodeDto,
  WorkspaceFinding,
  WorkspaceToken,
} from './findingsTree'
import { Finding, Section, Severity } from './types'

function range(startLine: number, startColumn = 0, endColumn = startColumn + 10): FindingTreeRange {
  return { startLine, startColumn, endLine: startLine, endColumn }
}

function makeFinding(overrides: Partial<Finding> & { id: string }): Finding {
  return {
    severity: overrides.severity ?? 'error',
    message: overrides.message ?? `finding ${overrides.id}`,
    ...overrides,
  }
}

function makeEntry(
  overrides: Partial<WorkspaceFinding> & { analyzerId: string; finding: Finding }
): WorkspaceFinding {
  return {
    filePath: overrides.filePath ?? 'src/example.ts',
    analyzerName: overrides.analyzerName ?? `${overrides.analyzerId} analyzer`,
    range: overrides.range ?? range(0),
    ...overrides,
  }
}

describe('buildTree', () => {
  describe('input guards', () => {
    it('returns an empty array for empty input', () => {
      expect(buildTree([])).toEqual([])
    })

    it('returns an empty array for nullish input', () => {
      expect(buildTree(undefined)).toEqual([])
      expect(buildTree(null)).toEqual([])
    })

    it('skips falsy entries inside the findings array', () => {
      const result = buildTree([
        undefined as unknown as WorkspaceFinding,
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.alg.none' }),
        }),
        null as unknown as WorkspaceFinding,
      ])
      expect(result).toHaveLength(1)
      expect(result[0].children).toHaveLength(1)
    })

    it('skips entries whose finding is missing', () => {
      const result = buildTree([
        {
          filePath: 'a.ts',
          analyzerId: 'jwt',
          analyzerName: 'JWT',
          range: range(0),
        } as unknown as WorkspaceFinding,
      ])
      expect(result).toEqual([])
    })
  })

  describe('grouping', () => {
    it('groups findings by analyzer id, one root per analyzer', () => {
      const result = buildTree([
        makeEntry({ analyzerId: 'jwt', finding: makeFinding({ id: 'jwt.a' }) }),
        makeEntry({ analyzerId: 'secret', finding: makeFinding({ id: 'secret.b' }) }),
        makeEntry({ analyzerId: 'jwt', finding: makeFinding({ id: 'jwt.c' }) }),
      ])
      expect(result).toHaveLength(2)
      const ids = result.map((r) => r.analyzerId).sort((a, b) => a.localeCompare(b))
      expect(ids).toEqual(['jwt', 'secret'])
    })

    it('uses the first analyzerName encountered for the group label', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          analyzerName: 'JSON Web Token',
          finding: makeFinding({ id: 'jwt.a' }),
        }),
        makeEntry({
          analyzerId: 'jwt',
          analyzerName: 'IGNORED (later occurrence)',
          finding: makeFinding({ id: 'jwt.b' }),
        }),
      ])
      expect(result[0].analyzerName).toBe('JSON Web Token')
      expect(result[0].label).toBe('JSON Web Token (2)')
    })

    it('emits a stable id of "analyzer:<id>" for the root and "analyzer:<id>:<index>" for children', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a' }),
          filePath: 'a.ts',
          range: range(0),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.b' }),
          filePath: 'a.ts',
          range: range(5),
        }),
      ])
      expect(result[0].id).toBe('analyzer:jwt')
      expect(result[0].children.map((c) => c.id)).toEqual([
        'analyzer:jwt:0',
        'analyzer:jwt:1',
      ])
    })
  })

  describe('analyzer root sort order', () => {
    it('sorts roots by total error count desc', () => {
      const result = buildTree([
        // analyzer A has 1 error
        makeEntry({
          analyzerId: 'a',
          finding: makeFinding({ id: 'a.1', severity: 'error' }),
        }),
        // analyzer B has 2 errors (should win)
        makeEntry({
          analyzerId: 'b',
          finding: makeFinding({ id: 'b.1', severity: 'error' }),
        }),
        makeEntry({
          analyzerId: 'b',
          finding: makeFinding({ id: 'b.2', severity: 'error' }),
        }),
      ])
      expect(result.map((r) => r.analyzerId)).toEqual(['b', 'a'])
    })

    it('breaks ties on errors with warning count desc', () => {
      const result = buildTree([
        // both analyzers have 1 error
        makeEntry({
          analyzerId: 'a',
          finding: makeFinding({ id: 'a.1', severity: 'error' }),
        }),
        makeEntry({
          analyzerId: 'b',
          finding: makeFinding({ id: 'b.1', severity: 'error' }),
        }),
        // analyzer A has 2 warnings
        makeEntry({
          analyzerId: 'a',
          finding: makeFinding({ id: 'a.2', severity: 'warning' }),
        }),
        makeEntry({
          analyzerId: 'a',
          finding: makeFinding({ id: 'a.3', severity: 'warning' }),
        }),
      ])
      expect(result.map((r) => r.analyzerId)).toEqual(['a', 'b'])
    })

    it('breaks ties on errors+warnings with info count desc', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'a',
          finding: makeFinding({ id: 'a.1', severity: 'info' }),
        }),
        makeEntry({
          analyzerId: 'b',
          finding: makeFinding({ id: 'b.1', severity: 'info' }),
        }),
        makeEntry({
          analyzerId: 'b',
          finding: makeFinding({ id: 'b.2', severity: 'info' }),
        }),
      ])
      expect(result.map((r) => r.analyzerId)).toEqual(['b', 'a'])
    })

    it('finally falls back to label ordering when severity counts all tie', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'zeta',
          analyzerName: 'Zeta analyzer',
          finding: makeFinding({ id: 'z.1', severity: 'error' }),
        }),
        makeEntry({
          analyzerId: 'alpha',
          analyzerName: 'Alpha analyzer',
          finding: makeFinding({ id: 'a.1', severity: 'error' }),
        }),
        makeEntry({
          analyzerId: 'middle',
          analyzerName: 'Middle analyzer',
          finding: makeFinding({ id: 'm.1', severity: 'error' }),
        }),
      ])
      expect(result.map((r) => r.analyzerName)).toEqual([
        'Alpha analyzer',
        'Middle analyzer',
        'Zeta analyzer',
      ])
    })

    it('records per-severity counts on every root', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a', severity: 'error' }),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.b', severity: 'warning' }),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.c', severity: 'info' }),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.d', severity: 'info' }),
        }),
      ])
      expect(result[0].errorCount).toBe(1)
      expect(result[0].warningCount).toBe(1)
      expect(result[0].infoCount).toBe(2)
      expect(result[0].label).toBe('jwt analyzer (4)')
    })
  })

  describe('child ordering within an analyzer', () => {
    it('sorts children by file path, then start line, then start column', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.b' }),
          filePath: 'src/b.ts',
          range: range(2),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a-line10' }),
          filePath: 'src/a.ts',
          range: range(10),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a-line2col0' }),
          filePath: 'src/a.ts',
          range: range(2, 0),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a-line2col5' }),
          filePath: 'src/a.ts',
          range: range(2, 5),
        }),
      ])
      const childIds = result[0].children.map((c) => c.findingId)
      expect(childIds).toEqual([
        'jwt.a-line2col0',
        'jwt.a-line2col5',
        'jwt.a-line10',
        'jwt.b',
      ])
    })

    it('does not mutate the input array order', () => {
      const input: WorkspaceFinding[] = [
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.b' }),
          filePath: 'b.ts',
          range: range(10),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a' }),
          filePath: 'a.ts',
          range: range(1),
        }),
      ]
      const snapshot = input.slice()
      buildTree(input)
      expect(input).toEqual(snapshot)
    })
  })

  describe('finding label format', () => {
    it('formats child labels as "[severity] message — path:line" (1-based line)', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({
            id: 'jwt.alg.none',
            severity: 'error',
            message: 'alg=none is unsafe',
          }),
          filePath: 'src/example.ts',
          range: range(12, 4),
        }),
      ])
      // startLine 12 (zero-based) → displayed as 13 (one-based)
      expect(result[0].children[0].label).toBe(
        '[error] alg=none is unsafe — src/example.ts:13'
      )
    })

    it('preserves the finding severity / id / message / filePath on the child DTO', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'secret',
          finding: makeFinding({
            id: 'secret.aws.accessKey',
            severity: 'warning',
            message: 'AKIA-prefixed key detected',
          }),
          filePath: 'config/.env',
          range: range(3, 5, 25),
        }),
      ])
      const child = result[0].children[0]
      expect(child.kind).toBe('finding')
      expect(child.severity).toBe('warning')
      expect(child.findingId).toBe('secret.aws.accessKey')
      expect(child.message).toBe('AKIA-prefixed key detected')
      expect(child.filePath).toBe('config/.env')
      expect(child.range).toEqual({
        startLine: 3,
        startColumn: 5,
        endLine: 3,
        endColumn: 25,
      })
    })

    it("emits a fresh range object on each child so the adapter can mutate freely", () => {
      const inputRange = range(0, 0, 10)
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a' }),
          range: inputRange,
        }),
      ])
      expect(result[0].children[0].range).not.toBe(inputRange)
      expect(result[0].children[0].range).toEqual(inputRange)
    })

    it('handles all three severities in the [severity] prefix', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a', severity: 'error', message: 'm-err' }),
          filePath: 'a.ts',
          range: range(0),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.b', severity: 'warning', message: 'm-warn' }),
          filePath: 'b.ts',
          range: range(0),
        }),
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.c', severity: 'info', message: 'm-info' }),
          filePath: 'c.ts',
          range: range(0),
        }),
      ])
      const labels = result[0].children.map((c) => c.label)
      expect(labels).toEqual([
        '[error] m-err — a.ts:1',
        '[warning] m-warn — b.ts:1',
        '[info] m-info — c.ts:1',
      ])
    })
  })

  describe('multi-analyzer end-to-end', () => {
    it('produces a fully-formed tree across multiple analyzers / files', () => {
      const findings: WorkspaceFinding[] = [
        // analyzer 'jwt' (2 errors, 1 warning) → ranks first
        makeEntry({
          analyzerId: 'jwt',
          analyzerName: 'JWT',
          finding: makeFinding({ id: 'jwt.a', severity: 'error', message: 'alg=none' }),
          filePath: 'src/a.ts',
          range: range(2),
        }),
        makeEntry({
          analyzerId: 'jwt',
          analyzerName: 'JWT',
          finding: makeFinding({ id: 'jwt.b', severity: 'error', message: 'expired' }),
          filePath: 'src/b.ts',
          range: range(7),
        }),
        makeEntry({
          analyzerId: 'jwt',
          analyzerName: 'JWT',
          finding: makeFinding({ id: 'jwt.c', severity: 'warning', message: 'weak alg' }),
          filePath: 'src/a.ts',
          range: range(5),
        }),
        // analyzer 'secret' (1 error) → ranks second
        makeEntry({
          analyzerId: 'secret',
          analyzerName: 'Secret',
          finding: makeFinding({ id: 'secret.aws', severity: 'error', message: 'AWS key leak' }),
          filePath: 'config/.env',
          range: range(1),
        }),
        // analyzer 'cookie' (info only) → ranks last
        makeEntry({
          analyzerId: 'cookie',
          analyzerName: 'Cookie',
          finding: makeFinding({ id: 'cookie.a', severity: 'info', message: 'missing Secure' }),
          filePath: 'src/server.ts',
          range: range(0),
        }),
      ]
      const result = buildTree(findings)
      expect(result.map((r) => r.analyzerId)).toEqual(['jwt', 'secret', 'cookie'])
      expect(result[0].label).toBe('JWT (3)')
      expect(result[1].label).toBe('Secret (1)')
      expect(result[2].label).toBe('Cookie (1)')

      // jwt children sorted by path then line
      const jwtChildren = result[0].children.map((c) => `${c.filePath}:${c.range!.startLine + 1}`)
      expect(jwtChildren).toEqual(['src/a.ts:3', 'src/a.ts:6', 'src/b.ts:8'])
    })
  })

  describe('shape constraints', () => {
    it('root nodes carry their children, finding nodes have an empty children array', () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a' }),
        }),
      ])
      expect(result[0].kind).toBe('analyzerRoot')
      expect(result[0].children).toHaveLength(1)
      expect(result[0].children[0].kind).toBe('finding')
      expect(result[0].children[0].children).toEqual([])
    })

    it("does not emit analyzer-specific fields on finding nodes", () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a' }),
        }),
      ])
      const child = result[0].children[0]
      expect(child.analyzerId).toBeUndefined()
      expect(child.analyzerName).toBeUndefined()
      expect(child.errorCount).toBeUndefined()
      expect(child.warningCount).toBeUndefined()
      expect(child.infoCount).toBeUndefined()
    })

    it("does not emit finding-specific fields on analyzer root nodes", () => {
      const result = buildTree([
        makeEntry({
          analyzerId: 'jwt',
          finding: makeFinding({ id: 'jwt.a' }),
        }),
      ])
      const root = result[0]
      expect(root.filePath).toBeUndefined()
      expect(root.range).toBeUndefined()
      expect(root.severity).toBeUndefined()
      expect(root.findingId).toBeUndefined()
      expect(root.message).toBeUndefined()
    })
  })

  describe('severity priority table', () => {
    it('exposes the priority ordering as a const', () => {
      expect(SEVERITY_RANK_TABLE.error).toBe(0)
      expect(SEVERITY_RANK_TABLE.warning).toBe(1)
      expect(SEVERITY_RANK_TABLE.info).toBe(2)
    })

    it('the table covers every Severity value', () => {
      const severities: Severity[] = ['error', 'warning', 'info']
      for (const sev of severities) {
        expect(typeof SEVERITY_RANK_TABLE[sev]).toBe('number')
      }
    })
  })
})

function token(overrides: Partial<WorkspaceToken> & { filePath: string }): WorkspaceToken {
  return {
    analyzerId: 'jwt',
    analyzerName: 'JWT',
    kind: 'JWS',
    range: range(0),
    sections: [],
    findings: [],
    ...overrides,
  }
}

function section(title: string, rows: Section['rows']): Section {
  return { id: title.toLowerCase(), title, rows }
}

describe('buildTokenTree', () => {
  it('returns [] for null / empty input', () => {
    expect(buildTokenTree(null)).toEqual([])
    expect(buildTokenTree(undefined)).toEqual([])
    expect(buildTokenTree([])).toEqual([])
  })

  it('emits one tokenRoot per token with kind suffix and file:line description', () => {
    const tokens: WorkspaceToken[] = [
      token({
        filePath: 'a.jwt',
        kind: 'JWS',
        range: range(0),
        sections: [section('Header', [{ key: 'alg', value: 'HS256' }])],
        findings: [],
      }),
    ]
    const roots = buildTokenTree(tokens)
    expect(roots).toHaveLength(1)
    expect(roots[0].kind).toBe('tokenRoot')
    expect(roots[0].label).toBe('JWT (JWS)')
    expect(roots[0].description).toBe('a.jwt:1')
    expect(roots[0].filePath).toBe('a.jwt')
  })

  it('nests sections as sectionGroup → sectionRow leaves', () => {
    const tokens = [
      token({
        filePath: 'x.jwt',
        sections: [
          section('Header', [
            { key: 'alg', value: 'HS256' },
            { key: 'typ', value: 'JWT' },
          ]),
          section('Claims', [{ key: 'sub', value: 'alice@example.com' }]),
        ],
      }),
    ]
    const [root] = buildTokenTree(tokens)
    expect(root.children).toHaveLength(2)
    expect(root.children[0].kind).toBe('sectionGroup')
    expect(root.children[0].label).toBe('Header')
    expect(root.children[0].children).toHaveLength(2)
    expect(root.children[0].children[0].kind).toBe('sectionRow')
    expect(root.children[0].children[0].label).toBe('alg')
    expect(root.children[0].children[0].description).toBe('HS256')
    expect(root.children[0].children[0].rowKey).toBe('alg')
    expect(root.children[0].children[0].rowValue).toBe('HS256')
    expect(root.children[1].label).toBe('Claims')
  })

  it('appends a findingsGroup with one finding leaf per finding', () => {
    const findings: Finding[] = [
      { id: 'jwt.alg.none', severity: 'error', message: 'alg=none not allowed' },
      { id: 'jwt.exp.soon', severity: 'warning', message: 'expires in 2 days' },
      { id: 'jwt.idp.entraV2', severity: 'info', message: 'Microsoft Entra ID v2' },
    ]
    const tokens = [token({ filePath: 't.jwt', findings })]
    const [root] = buildTokenTree(tokens)
    expect(root.errorCount).toBe(1)
    expect(root.warningCount).toBe(1)
    expect(root.infoCount).toBe(1)
    const group = root.children.find((c) => c.kind === 'findingsGroup')
    expect(group).toBeDefined()
    expect(group!.label).toBe('Findings (3)')
    expect(group!.children).toHaveLength(3)
    expect(group!.children[0].kind).toBe('finding')
    expect(group!.children[0].label).toBe('[error] alg=none not allowed')
    expect(group!.children[0].severity).toBe('error')
    expect(group!.children[0].findingId).toBe('jwt.alg.none')
    expect(group!.children[0].filePath).toBe('t.jwt')
  })

  it('omits the findingsGroup when there are no findings', () => {
    const tokens = [token({ filePath: 'clean.jwt', findings: [] })]
    const [root] = buildTokenTree(tokens)
    expect(root.children.find((c) => c.kind === 'findingsGroup')).toBeUndefined()
  })

  it('sorts tokens by file path then start line', () => {
    const tokens: WorkspaceToken[] = [
      token({ filePath: 'b.jwt', range: range(0) }),
      token({ filePath: 'a.jwt', range: range(5) }),
      token({ filePath: 'a.jwt', range: range(0) }),
    ]
    const roots = buildTokenTree(tokens)
    expect(roots.map((r) => r.description)).toEqual(['a.jwt:1', 'a.jwt:6', 'b.jwt:1'])
  })

  it('stringifies row values safely (null / object / number / boolean)', () => {
    const tokens = [
      token({
        filePath: 'mix.jwt',
        sections: [
          section('mix', [
            { key: 'null', value: null },
            { key: 'obj', value: { a: 1 } },
            { key: 'num', value: 42 },
            { key: 'bool', value: true },
            { key: 'undef', value: undefined },
          ]),
        ],
      }),
    ]
    const [root] = buildTokenTree(tokens)
    const rows = root.children[0].children
    expect(rows[0].description).toBe('')
    expect(rows[1].description).toBe('{"a":1}')
    expect(rows[2].description).toBe('42')
    expect(rows[3].description).toBe('true')
    expect(rows[4].description).toBe('')
  })

  it('truncates long row values', () => {
    const longString = 'x'.repeat(200)
    const tokens = [
      token({
        filePath: 'long.jwt',
        sections: [section('long', [{ key: 'k', value: longString }])],
      }),
    ]
    const [root] = buildTokenTree(tokens)
    const desc = root.children[0].children[0].description ?? ''
    expect(desc.length).toBeLessThanOrEqual(120)
    expect(desc.endsWith('…')).toBe(true)
  })

  it('forwards section row description into rowDescription', () => {
    const tokens = [
      token({
        filePath: 'desc.jwt',
        sections: [section('s', [{ key: 'k', value: 'v', description: 'helpful text' }])],
      }),
    ]
    const [root] = buildTokenTree(tokens)
    expect(root.children[0].children[0].rowDescription).toBe('helpful text')
  })

  it('omits kind suffix when the analyzer did not provide one', () => {
    const tokens = [token({ filePath: 'k.jwt', kind: '' })]
    const [root] = buildTokenTree(tokens)
    expect(root.label).toBe('JWT')
  })
})

// Type-only smoke: ensure the exported types are consumable from tests.
// `satisfies` keeps the literal narrow while asserting `TreeNodeDto` shape.
const _typecheckTree = {
  id: 'analyzer:jwt',
  kind: 'analyzerRoot',
  label: 'JWT (0)',
  analyzerId: 'jwt',
  analyzerName: 'JWT',
  errorCount: 0,
  warningCount: 0,
  infoCount: 0,
  children: [],
} satisfies TreeNodeDto
