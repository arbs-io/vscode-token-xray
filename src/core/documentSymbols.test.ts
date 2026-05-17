import { describe, expect, it } from 'vitest'
import {
  buildDocumentSymbolDtos,
  DocumentSymbolHit,
  MAX_SYMBOL_NAME_LENGTH,
} from './documentSymbols'
import { Section } from './types'

function makeHit(overrides: Partial<DocumentSymbolHit> & { analyzerId: string }): DocumentSymbolHit {
  return {
    analyzerName: overrides.analyzerName ?? `${overrides.analyzerId} analyzer`,
    startLine: 1,
    startColumn: 0,
    endLine: 1,
    endColumn: 80,
    ...overrides,
  }
}

function makeSection(overrides: Partial<Section> = {}): Section {
  return {
    id: overrides.id ?? 'payload',
    title: overrides.title ?? 'Claims',
    rows: overrides.rows ?? [],
  }
}

describe('buildDocumentSymbolDtos', () => {
  describe('symbol kind heuristic', () => {
    it("returns 'Constant' for x509 / PASETO / JWK / cookie / secret", () => {
      const ids = ['x509', 'paseto', 'jwk', 'cookie', 'secret']
      for (const id of ids) {
        const dtos = buildDocumentSymbolDtos([makeHit({ analyzerId: id })])
        expect(dtos[0].kind, `expected ${id} → Constant`).toBe('Constant')
      }
    })

    it("returns 'Object' for SAML / oidcDiscovery / samlMetadata", () => {
      const ids = ['saml', 'oidcDiscovery', 'samlMetadata']
      for (const id of ids) {
        const dtos = buildDocumentSymbolDtos([makeHit({ analyzerId: id })])
        expect(dtos[0].kind, `expected ${id} → Object`).toBe('Object')
      }
    })

    it("returns 'Key' for everything else (jwt, oauth, basicAuth, awsSigv4, csr, sshKey, pgp, httpSignature)", () => {
      const ids = [
        'jwt',
        'oauth',
        'basicAuth',
        'awsSigv4',
        'csr',
        'sshKey',
        'pgp',
        'httpSignature',
      ]
      for (const id of ids) {
        const dtos = buildDocumentSymbolDtos([makeHit({ analyzerId: id })])
        expect(dtos[0].kind, `expected ${id} → Key`).toBe('Key')
      }
    })

    it("returns 'String' for an empty analyzer id", () => {
      const dtos = buildDocumentSymbolDtos([makeHit({ analyzerId: '' })])
      expect(dtos[0].kind).toBe('String')
    })
  })

  describe('name composition', () => {
    it('formats the name as "<analyzerName>: <first row value>"', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          analyzerName: 'JSON Web Token (JWT)',
          firstSection: makeSection({
            rows: [{ key: 'alg', value: 'RS256' }],
          }),
        }),
      ])
      expect(dtos[0].name).toBe('JSON Web Token (JWT): RS256')
    })

    it("falls back to 'token' when the firstSection is absent", () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({ analyzerId: 'jwt', analyzerName: 'JSON Web Token (JWT)' }),
      ])
      expect(dtos[0].name).toBe('JSON Web Token (JWT): token')
    })

    it("falls back to 'token' when firstSection rows is empty", () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          analyzerName: 'JSON Web Token (JWT)',
          firstSection: makeSection({ rows: [] }),
        }),
      ])
      expect(dtos[0].name).toBe('JSON Web Token (JWT): token')
    })

    it("falls back to 'token' when the first row's value is undefined / null / empty", () => {
      const cases: Array<{ value: unknown; description: string }> = [
        { value: undefined, description: 'undefined' },
        { value: null, description: 'null' },
        { value: '', description: 'empty string' },
        { value: '   ', description: 'whitespace-only string' },
      ]
      for (const { value, description } of cases) {
        const dtos = buildDocumentSymbolDtos([
          makeHit({
            analyzerId: 'jwt',
            analyzerName: 'JSON Web Token (JWT)',
            firstSection: makeSection({ rows: [{ key: 'alg', value }] }),
          }),
        ])
        expect(dtos[0].name, `value=${description}`).toBe('JSON Web Token (JWT): token')
      }
    })

    it('renders numeric and boolean values via String()', () => {
      const dtosNumber = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          analyzerName: 'JWT',
          firstSection: makeSection({ rows: [{ key: 'exp', value: 1735689600 }] }),
        }),
      ])
      expect(dtosNumber[0].name).toBe('JWT: 1735689600')

      const dtosBool = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'cookie',
          analyzerName: 'HTTP cookie',
          firstSection: makeSection({ rows: [{ key: 'secure', value: true }] }),
        }),
      ])
      expect(dtosBool[0].name).toBe('HTTP cookie: true')
    })

    it('JSON-serialises object / array values so the outline still shows something', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'samlMetadata',
          analyzerName: 'SAML metadata',
          firstSection: makeSection({
            rows: [{ key: 'roles', value: ['idp', 'sp'] }],
          }),
        }),
      ])
      expect(dtos[0].name).toBe('SAML metadata: ["idp","sp"]')
    })

    it('returns [unrenderable] when the value cannot be JSON-serialised', () => {
      const circular: Record<string, unknown> = {}
      circular.self = circular
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          analyzerName: 'JWT',
          firstSection: makeSection({ rows: [{ key: 'meta', value: circular }] }),
        }),
      ])
      expect(dtos[0].name).toBe('JWT: [unrenderable]')
    })

    it('truncates names longer than 60 chars with a trailing ellipsis', () => {
      const longValue = 'a'.repeat(200)
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          analyzerName: 'JSON Web Token',
          firstSection: makeSection({ rows: [{ key: 'sub', value: longValue }] }),
        }),
      ])
      expect(dtos[0].name.length).toBe(MAX_SYMBOL_NAME_LENGTH)
      expect(dtos[0].name.endsWith('…')).toBe(true)
      expect(dtos[0].name.startsWith('JSON Web Token: ')).toBe(true)
    })

    it('does not truncate when the rendered name is exactly the limit', () => {
      // analyzerName.length=10 + ': '=2 → prefix=12; pad value to fill exactly 60
      const valueLen = MAX_SYMBOL_NAME_LENGTH - 'JSON-Web-T: '.length
      const value = 'x'.repeat(valueLen)
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          analyzerName: 'JSON-Web-T',
          firstSection: makeSection({ rows: [{ key: 'sub', value }] }),
        }),
      ])
      expect(dtos[0].name.length).toBe(MAX_SYMBOL_NAME_LENGTH)
      expect(dtos[0].name.endsWith('…')).toBe(false)
    })
  })

  describe('detail composition (finding counts)', () => {
    it('is undefined when there are no findings', () => {
      const dtos = buildDocumentSymbolDtos([makeHit({ analyzerId: 'jwt', findings: [] })])
      expect(dtos[0].detail).toBeUndefined()

      const dtos2 = buildDocumentSymbolDtos([makeHit({ analyzerId: 'jwt' })])
      expect(dtos2[0].detail).toBeUndefined()
    })

    it('renders the single error case as "1 finding (1 error)"', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          findings: [{ id: 'jwt.alg.none', severity: 'error', message: 'alg=none' }],
        }),
      ])
      expect(dtos[0].detail).toBe('1 finding (1 error)')
    })

    it('pluralises and reports both errors and warnings', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          findings: [
            { id: 'a', severity: 'error', message: 'e1' },
            { id: 'b', severity: 'error', message: 'e2' },
            { id: 'c', severity: 'warning', message: 'w1' },
          ],
        }),
      ])
      expect(dtos[0].detail).toBe('3 findings (2 errors, 1 warning)')
    })

    it('omits the severity breakdown when the only findings are info', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          findings: [
            { id: 'a', severity: 'info', message: 'info1' },
            { id: 'b', severity: 'info', message: 'info2' },
          ],
        }),
      ])
      expect(dtos[0].detail).toBe('2 findings')
    })

    it('reports only-warnings without an error count', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          findings: [
            { id: 'a', severity: 'warning', message: 'w1' },
            { id: 'b', severity: 'warning', message: 'w2' },
          ],
        }),
      ])
      expect(dtos[0].detail).toBe('2 findings (2 warnings)')
    })
  })

  describe('range mapping', () => {
    it('mirrors the hit range into range and selectionRange (independent copies)', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({
          analyzerId: 'jwt',
          startLine: 3,
          startColumn: 5,
          endLine: 3,
          endColumn: 87,
        }),
      ])
      expect(dtos[0].range).toEqual({
        startLine: 3,
        startColumn: 5,
        endLine: 3,
        endColumn: 87,
      })
      expect(dtos[0].selectionRange).toEqual(dtos[0].range)
      // selectionRange must be a fresh object so the provider can mutate it
      // without leaking back into range.
      expect(dtos[0].selectionRange).not.toBe(dtos[0].range)
    })
  })

  describe('per-analyzer kind examples (smoke)', () => {
    const cases: Array<{ id: string; name: string; firstRowValue: string; expected: string }> = [
      { id: 'jwt', name: 'JSON Web Token (JWT)', firstRowValue: 'RS256', expected: 'Key' },
      { id: 'paseto', name: 'PASETO', firstRowValue: 'v4', expected: 'Constant' },
      { id: 'x509', name: 'X.509 certificate (PEM)', firstRowValue: 'CN=example', expected: 'Constant' },
      { id: 'jwk', name: 'JSON Web Key (JWK / JWKS)', firstRowValue: 'kty=RSA', expected: 'Constant' },
      { id: 'cookie', name: 'HTTP cookie (Set-Cookie)', firstRowValue: 'session', expected: 'Constant' },
      { id: 'secret', name: 'Secret / credential', firstRowValue: 'AWS access key', expected: 'Constant' },
      { id: 'saml', name: 'SAML 2.0', firstRowValue: 'Response', expected: 'Object' },
      { id: 'oidcDiscovery', name: 'OIDC discovery', firstRowValue: 'issuer', expected: 'Object' },
      { id: 'samlMetadata', name: 'SAML 2.0 metadata', firstRowValue: 'EntityDescriptor', expected: 'Object' },
      { id: 'oauth', name: 'OAuth token', firstRowValue: 'github_pat', expected: 'Key' },
      { id: 'basicAuth', name: 'HTTP Basic credentials', firstRowValue: 'alice', expected: 'Key' },
      { id: 'awsSigv4', name: 'AWS Signature v4', firstRowValue: 'AWS4-HMAC-SHA256', expected: 'Key' },
      { id: 'csr', name: 'Certificate Signing Request', firstRowValue: 'CN=req', expected: 'Key' },
      { id: 'sshKey', name: 'OpenSSH public key', firstRowValue: 'ssh-ed25519', expected: 'Key' },
      { id: 'pgp', name: 'OpenPGP', firstRowValue: 'PUBLIC KEY BLOCK', expected: 'Key' },
      { id: 'httpSignature', name: 'HTTP Signature', firstRowValue: 'keyId=test', expected: 'Key' },
    ]

    for (const c of cases) {
      it(`maps ${c.id} → kind=${c.expected} with name composed from analyzerName + first row`, () => {
        const dtos = buildDocumentSymbolDtos([
          makeHit({
            analyzerId: c.id,
            analyzerName: c.name,
            firstSection: makeSection({ rows: [{ key: 'first', value: c.firstRowValue }] }),
          }),
        ])
        expect(dtos[0].kind).toBe(c.expected)
        expect(dtos[0].name).toBe(`${c.name}: ${c.firstRowValue}`)
      })
    }
  })

  describe('input guards', () => {
    it('returns an empty array for an empty hit list', () => {
      expect(buildDocumentSymbolDtos([])).toEqual([])
    })

    it('returns an empty array when the hits argument is nullish', () => {
      expect(buildDocumentSymbolDtos(undefined as unknown as DocumentSymbolHit[])).toEqual([])
      expect(buildDocumentSymbolDtos(null as unknown as DocumentSymbolHit[])).toEqual([])
    })

    it('skips falsy entries inside a hits array', () => {
      const dtos = buildDocumentSymbolDtos([
        undefined as unknown as DocumentSymbolHit,
        makeHit({ analyzerId: 'jwt', analyzerName: 'JWT' }),
        null as unknown as DocumentSymbolHit,
      ])
      expect(dtos).toHaveLength(1)
      expect(dtos[0].name).toBe('JWT: token')
    })

    it('produces one DTO per hit, preserving input order', () => {
      const dtos = buildDocumentSymbolDtos([
        makeHit({ analyzerId: 'jwt', analyzerName: 'JWT', startLine: 1 }),
        makeHit({ analyzerId: 'x509', analyzerName: 'X.509', startLine: 5 }),
        makeHit({ analyzerId: 'saml', analyzerName: 'SAML', startLine: 10 }),
      ])
      expect(dtos).toHaveLength(3)
      expect(dtos.map((d) => d.kind)).toEqual(['Key', 'Constant', 'Object'])
      expect(dtos.map((d) => d.range.startLine)).toEqual([1, 5, 10])
    })
  })
})
