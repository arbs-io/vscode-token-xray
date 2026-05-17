import { describe, expect, it } from 'vitest'
import { buildHoverMarkdown } from './buildHoverMarkdown'
import { AnalysisResult } from './types'

function makeResult(overrides: Partial<AnalysisResult> & { analyzerId: string }): AnalysisResult {
  return {
    kind: 'detection',
    sections: [],
    findings: [],
    ...overrides,
  }
}

describe('buildHoverMarkdown', () => {
  describe('header line', () => {
    it('uppercases the analyzer id and shows the kind', () => {
      const md = buildHoverMarkdown(
        makeResult({ analyzerId: 'jwt', kind: 'JWS', sections: [], findings: [] })
      )
      expect(md).toContain('**JWT** — JWS')
    })

    it('falls back to "detection" when kind is undefined', () => {
      const md = buildHoverMarkdown(
        makeResult({ analyzerId: 'jwt', kind: undefined as unknown })
      )
      expect(md).toContain('**JWT** — detection')
    })
  })

  describe('per-analyzer kind', () => {
    it('renders a JWT result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'header',
              title: 'JOSE Header',
              rows: [
                { key: 'alg', value: 'RS256', description: 'Signature algorithm' },
                { key: 'typ', value: 'JWT' },
              ],
            },
          ],
          findings: [{ id: 'jwt.alg.none', severity: 'error', message: 'alg is none' }],
        })
      )
      expect(md).toContain('**JWT** — JWS')
      expect(md).toContain('### JOSE Header')
      expect(md).toContain('| Key | Value |')
      expect(md).toContain('| alg | RS256 _(Signature algorithm)_ |')
      expect(md).toContain('| typ | JWT |')
      expect(md).toContain('### Findings')
      expect(md).toContain('🔴 `jwt.alg.none` — alg is none')
    })

    it('renders a SAML result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'saml',
          kind: 'Response',
          sections: [
            {
              id: 'overview',
              title: 'SAML Overview',
              rows: [
                { key: 'issuer', value: 'https://idp.example.com', description: 'Identity Provider' },
                { key: 'signature', value: 'present (sha256)', description: 'Signature' },
              ],
            },
          ],
          findings: [
            { id: 'saml.signature.weak', severity: 'warning', message: 'SHA-1 signature' },
          ],
        })
      )
      expect(md).toContain('**SAML** — Response')
      expect(md).toContain('### SAML Overview')
      expect(md).toContain('| issuer | https://idp.example.com _(Identity Provider)_ |')
      expect(md).toContain('🟠 `saml.signature.weak` — SHA-1 signature')
    })

    it('renders an X509 result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'x509',
          kind: 'leaf',
          sections: [
            {
              id: 'certificate',
              title: 'Certificate',
              rows: [
                { key: 'subject', value: 'CN=example.com', description: 'Subject DN' },
                { key: 'keyAlgorithm', value: 'rsaEncryption' },
              ],
            },
          ],
          findings: [],
        })
      )
      expect(md).toContain('**X509** — leaf')
      expect(md).toContain('### Certificate')
      expect(md).toContain('| subject | CN=example.com _(Subject DN)_ |')
      // No findings section when findings is empty.
      expect(md).not.toContain('### Findings')
    })

    it('renders a JWK result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwk',
          kind: 'JWK',
          sections: [
            {
              id: 'key-0',
              title: 'Key #1 (RSA)',
              rows: [
                { key: 'kty', value: 'RSA', description: 'Key type' },
                { key: 'keySizeBits', value: 2048 },
              ],
            },
          ],
          findings: [
            { id: 'jwk.key.private', severity: 'error', message: 'Private material present' },
          ],
        })
      )
      expect(md).toContain('**JWK** — JWK')
      expect(md).toContain('### Key #1 (RSA)')
      expect(md).toContain('| keySizeBits | 2048 |')
      expect(md).toContain('🔴 `jwk.key.private` — Private material present')
    })

    it('renders an OAuth result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'oauth',
          kind: 'github',
          sections: [
            {
              id: 'token',
              title: 'Token',
              rows: [
                { key: 'vendor', value: 'github', description: 'Issuing service' },
                { key: 'environment', value: 'live', description: 'LIVE / production' },
              ],
            },
          ],
          findings: [
            { id: 'oauth.github.pat', severity: 'error', message: 'GitHub PAT (live)' },
          ],
        })
      )
      expect(md).toContain('**OAUTH** — github')
      expect(md).toContain('### Token')
      expect(md).toContain('| environment | live _(LIVE / production)_ |')
      expect(md).toContain('🔴 `oauth.github.pat` — GitHub PAT (live)')
    })

    it('renders a cookie result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'cookie',
          kind: 'sessionId',
          sections: [
            {
              id: 'cookie',
              title: 'Cookie: sessionId',
              rows: [
                { key: 'name', value: 'sessionId', description: 'Cookie name' },
                { key: 'secure', value: 'false', description: 'Secure attribute' },
              ],
            },
          ],
          findings: [
            { id: 'cookie.secure.missing', severity: 'warning', message: 'Missing Secure' },
          ],
        })
      )
      expect(md).toContain('**COOKIE** — sessionId')
      expect(md).toContain('### Cookie: sessionId')
      expect(md).toContain('| secure | false _(Secure attribute)_ |')
      expect(md).toContain('🟠 `cookie.secure.missing` — Missing Secure')
    })

    it('renders a secret result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'secret',
          kind: 'aws',
          sections: [
            {
              id: 'secret',
              title: 'AWS Access Key',
              rows: [
                { key: 'rule', value: 'aws.accessKey.AKIA', description: 'Rule id' },
                { key: 'severity', value: 'error', description: 'Severity' },
              ],
            },
          ],
          findings: [
            {
              id: 'aws.accessKey.AKIA',
              severity: 'error',
              message: 'AWS access key id',
              docUrl: 'https://example/docs',
            },
          ],
        })
      )
      expect(md).toContain('**SECRET** — aws')
      expect(md).toContain('### AWS Access Key')
      expect(md).toContain('| rule | aws.accessKey.AKIA _(Rule id)_ |')
      expect(md).toContain('🔴 `aws.accessKey.AKIA` — AWS access key id [docs](https://example/docs)')
    })

    it('renders a paseto result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'paseto',
          kind: 'PASETO v4.public',
          sections: [
            {
              id: 'header',
              title: 'Header',
              rows: [
                { key: 'version', value: 'v4', description: 'PASETO protocol version' },
                { key: 'purpose', value: 'public' },
              ],
            },
          ],
          findings: [
            { id: 'paseto.purpose.local', severity: 'info', message: 'Local purpose' },
          ],
        })
      )
      expect(md).toContain('**PASETO** — PASETO v4.public')
      expect(md).toContain('### Header')
      expect(md).toContain('| version | v4 _(PASETO protocol version)_ |')
      expect(md).toContain('🔵 `paseto.purpose.local` — Local purpose')
    })

    it('renders a basicAuth result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'basicAuth',
          kind: 'HTTP Basic',
          sections: [
            {
              id: 'credentials',
              title: 'Credentials',
              rows: [
                { key: 'username', value: 'admin', description: 'Decoded username' },
                { key: 'password (masked)', value: '********ab' },
              ],
            },
          ],
          findings: [
            { id: 'basic.cred.plaintext', severity: 'error', message: 'Plaintext basic credentials' },
          ],
        })
      )
      expect(md).toContain('**BASICAUTH** — HTTP Basic')
      expect(md).toContain('### Credentials')
      expect(md).toContain('| password (masked) | ********ab |')
      expect(md).toContain('🔴 `basic.cred.plaintext` — Plaintext basic credentials')
    })

    it('renders an awsSigv4 result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'awsSigv4',
          kind: 'AWS SigV4',
          sections: [
            {
              id: 'signature',
              title: 'Signature',
              rows: [
                { key: 'accessKeyId', value: 'AKIA1234', description: 'AWS access key id' },
                { key: 'region', value: 'us-east-1' },
              ],
            },
          ],
          findings: [
            {
              id: 'awsSigv4.accessKeyExposed',
              severity: 'warning',
              message: 'Access key id is plaintext in the header',
            },
          ],
        })
      )
      expect(md).toContain('**AWSSIGV4** — AWS SigV4')
      expect(md).toContain('### Signature')
      expect(md).toContain('| accessKeyId | AKIA1234 _(AWS access key id)_ |')
      expect(md).toContain('🟠 `awsSigv4.accessKeyExposed` — Access key id is plaintext in the header')
    })

    it('renders a csr result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'csr',
          kind: 'PKCS#10 CSR',
          sections: [
            {
              id: 'subjectKey',
              title: 'Subject & Key',
              rows: [
                { key: 'subject', value: 'CN=foo', description: 'Subject DN' },
                { key: 'algorithm', value: 'RSA' },
              ],
            },
          ],
          findings: [
            { id: 'csr.key.weakRsa', severity: 'error', message: 'RSA < 2048 bits' },
          ],
        })
      )
      expect(md).toContain('**CSR** — PKCS#10 CSR')
      expect(md).toContain('### Subject & Key')
      expect(md).toContain('| subject | CN=foo _(Subject DN)_ |')
      expect(md).toContain('🔴 `csr.key.weakRsa` — RSA < 2048 bits')
    })

    it('renders an sshKey result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'sshKey',
          kind: 'OpenSSH public key',
          sections: [
            {
              id: 'key',
              title: 'Key',
              rows: [
                { key: 'type', value: 'ssh-ed25519', description: 'OpenSSH algorithm' },
              ],
            },
          ],
          findings: [
            { id: 'sshKey.weakDsa', severity: 'error', message: 'DSA is deprecated' },
          ],
        })
      )
      expect(md).toContain('**SSHKEY** — OpenSSH public key')
      expect(md).toContain('### Key')
      expect(md).toContain('| type | ssh-ed25519 _(OpenSSH algorithm)_ |')
      expect(md).toContain('🔴 `sshKey.weakDsa` — DSA is deprecated')
    })

    it('renders a pgp result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'pgp',
          kind: 'OpenPGP public key',
          sections: [
            {
              id: 'block',
              title: 'Block',
              rows: [
                { key: 'blockType', value: 'PUBLIC KEY BLOCK', description: 'OpenPGP block type' },
              ],
            },
          ],
          findings: [
            { id: 'pgp.privateKey.present', severity: 'error', message: 'Private key in armor' },
          ],
        })
      )
      expect(md).toContain('**PGP** — OpenPGP public key')
      expect(md).toContain('### Block')
      expect(md).toContain('| blockType | PUBLIC KEY BLOCK _(OpenPGP block type)_ |')
      expect(md).toContain('🔴 `pgp.privateKey.present` — Private key in armor')
    })

    it('renders an oidcDiscovery result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'oidcDiscovery',
          kind: 'OIDC discovery document',
          sections: [
            {
              id: 'overview',
              title: 'Endpoints',
              rows: [
                { key: 'issuer', value: 'https://idp.example.com', description: 'OIDC issuer' },
              ],
            },
          ],
          findings: [
            { id: 'oidcDiscovery.algs.noneAllowed', severity: 'error', message: 'none alg' },
          ],
        })
      )
      expect(md).toContain('**OIDCDISCOVERY** — OIDC discovery document')
      expect(md).toContain('### Endpoints')
      expect(md).toContain('| issuer | https://idp.example.com _(OIDC issuer)_ |')
      expect(md).toContain('🔴 `oidcDiscovery.algs.noneAllowed` — none alg')
    })

    it('renders a samlMetadata result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'samlMetadata',
          kind: 'EntityDescriptor (IDPSSO)',
          sections: [
            {
              id: 'entity-0',
              title: 'Entity 1: https://idp.example.com',
              rows: [
                { key: 'entityID', value: 'https://idp.example.com', description: 'Entity id' },
              ],
            },
          ],
          findings: [
            { id: 'samlMeta.signing.missing', severity: 'warning', message: 'No signature' },
          ],
        })
      )
      expect(md).toContain('**SAMLMETADATA** — EntityDescriptor (IDPSSO)')
      expect(md).toContain('### Entity 1: https://idp.example.com')
      expect(md).toContain('| entityID | https://idp.example.com _(Entity id)_ |')
      expect(md).toContain('🟠 `samlMeta.signing.missing` — No signature')
    })

    it('renders a httpSignature result', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'httpSignature',
          kind: 'HTTP Signature (Cavage)',
          sections: [
            {
              id: 'signature',
              title: 'Signature',
              rows: [
                { key: 'keyId', value: 'rsa-key-1', description: 'Verifier key' },
                { key: 'algorithm', value: 'hmac-sha1' },
              ],
            },
          ],
          findings: [
            { id: 'httpSignature.algorithm.weak', severity: 'warning', message: 'Weak alg' },
          ],
        })
      )
      expect(md).toContain('**HTTPSIGNATURE** — HTTP Signature (Cavage)')
      expect(md).toContain('### Signature')
      expect(md).toContain('| algorithm | hmac-sha1 |')
      expect(md).toContain('🟠 `httpSignature.algorithm.weak` — Weak alg')
    })
  })

  describe('edge cases', () => {
    it('omits the findings block when there are no findings', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 'header',
              title: 'JOSE Header',
              rows: [{ key: 'alg', value: 'RS256' }],
            },
          ],
          findings: [],
        })
      )
      expect(md).toContain('### JOSE Header')
      expect(md).not.toContain('### Findings')
    })

    it('renders only the header when there are neither sections nor findings', () => {
      const md = buildHoverMarkdown(makeResult({ analyzerId: 'jwt', kind: 'JWS' }))
      expect(md).toBe('**JWT** — JWS')
    })

    it('omits the table rows for a section with no rows but keeps the heading', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [{ id: 'empty', title: 'Empty', rows: [] }],
        })
      )
      expect(md).toContain('### Empty')
      expect(md).not.toContain('| Key | Value |')
    })

    it('renders all three severity rows together', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          findings: [
            { id: 'a.err', severity: 'error', message: 'err msg' },
            { id: 'b.warn', severity: 'warning', message: 'warn msg' },
            { id: 'c.info', severity: 'info', message: 'info msg' },
          ],
        })
      )
      expect(md).toContain('🔴 `a.err` — err msg')
      expect(md).toContain('🟠 `b.warn` — warn msg')
      expect(md).toContain('🔵 `c.info` — info msg')
    })

    it('escapes pipes and newlines in cell values', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 's',
              title: 'S',
              rows: [{ key: 'k', value: 'a|b\nc' }],
            },
          ],
        })
      )
      expect(md).toContain('| k | a\\|b<br>c |')
    })

    it('renders null / undefined values as _(none)_', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 's',
              title: 'S',
              rows: [
                { key: 'a', value: null },
                { key: 'b', value: undefined },
              ],
            },
          ],
        })
      )
      expect(md).toContain('| a | _(none)_ |')
      expect(md).toContain('| b | _(none)_ |')
    })

    it('renders object values as fenced JSON', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 's',
              title: 'S',
              rows: [{ key: 'obj', value: { a: 1 } }],
            },
          ],
        })
      )
      expect(md).toContain('| obj | `{"a":1}` |')
    })

    it('renders array values as a comma-joined list', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          sections: [
            {
              id: 's',
              title: 'S',
              rows: [{ key: 'arr', value: ['a', 'b', 'c'] }],
            },
          ],
        })
      )
      expect(md).toContain('| arr | a, b, c |')
    })

    it('handles a finding without an id', () => {
      const md = buildHoverMarkdown(
        makeResult({
          analyzerId: 'jwt',
          kind: 'JWS',
          findings: [{ id: '', severity: 'info', message: 'plain msg' }],
        })
      )
      expect(md).toContain('### Findings')
      expect(md).toContain('🔵 — plain msg')
    })
  })
})
