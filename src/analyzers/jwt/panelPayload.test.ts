import { SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'
import {
  augmentWithVerification,
  buildJwtPanelPayload,
  findingsBySeverity,
} from './panelPayload'
import { VerifyKeySource } from './verify'

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
}

const NOW = Date.UTC(2026, 0, 1)

describe('buildJwtPanelPayload', () => {
  it('produces header, claims, and findings for a JWS', () => {
    const token = `${b64u({ alg: 'RS256', kid: 'k1' })}.${b64u({
      iss: 'me',
      aud: 'you',
      exp: Math.floor(NOW / 1000) + 3600,
    })}.sig`
    const payload = buildJwtPanelPayload(token, { now: NOW })
    expect(payload.kind).toBe('JWS')
    expect(payload.header.alg).toBe('RS256')
    expect(payload.claims).not.toBeNull()
    expect(payload.claims!.iss).toBe('me')
    expect(payload.isEncrypted).toBe(false)
    expect(payload.findings).toEqual([])
  })

  it('marks JWE payloads as encrypted with null claims', () => {
    const token = `${b64u({ alg: 'RSA-OAEP', enc: 'A256GCM' })}.encKey.iv.ct.tag`
    const payload = buildJwtPanelPayload(token, { now: NOW })
    expect(payload.kind).toBe('JWE')
    expect(payload.isEncrypted).toBe(true)
    expect(payload.claims).toBeNull()
  })

  it('surfaces findings (alg:none)', () => {
    const token = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`
    const payload = buildJwtPanelPayload(token, { now: NOW })
    const ids = payload.findings.map((f) => f.id)
    expect(ids).toContain('jwt.alg.none')
  })

  it('throws when input is not a JWT', () => {
    expect(() => buildJwtPanelPayload('not a token')).toThrow(/does not look like a JWT/)
  })
})

describe('augmentWithVerification', () => {
  const SECRET = 'super-secret-shared-key-1234567890'

  async function signedToken(alg = 'HS256'): Promise<string> {
    return new SignJWT({ sub: 'a' })
      .setProtectedHeader({ alg })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode(SECRET))
  }

  it('prepends a verified finding when signature is valid', async () => {
    const token = await signedToken()
    const payload = buildJwtPanelPayload(token)
    const keys: VerifyKeySource[] = [{ kind: 'symmetric', secret: SECRET, alg: 'HS256' }]
    const augmented = await augmentWithVerification(payload, token, keys)
    expect(augmented.findings[0].id).toBe('jwt.signature.verified')
    expect(augmented.findings[0].severity).toBe('info')
  })

  it('prepends an error finding when signature is invalid', async () => {
    const token = await signedToken()
    const payload = buildJwtPanelPayload(token)
    const keys: VerifyKeySource[] = [
      { kind: 'symmetric', secret: 'wrong-secret-wrong-secret-wrong-secret', alg: 'HS256' },
    ]
    const augmented = await augmentWithVerification(payload, token, keys)
    expect(augmented.findings[0].id).toBe('jwt.signature.invalid')
    expect(augmented.findings[0].severity).toBe('error')
  })

  it('returns the payload unchanged when no keys configured', async () => {
    const token = await signedToken()
    const payload = buildJwtPanelPayload(token)
    const augmented = await augmentWithVerification(payload, token, [])
    expect(augmented).toBe(payload)
  })

  it('returns the payload unchanged for JWE', async () => {
    const jwe = `${Buffer.from(JSON.stringify({ alg: 'RSA-OAEP', enc: 'A256GCM' }))
      .toString('base64')
      .replace(/=+$/, '')
      .replaceAll('+', '-')
      .replaceAll('/', '_')}.k.iv.ct.tag`
    const payload = buildJwtPanelPayload(jwe)
    const keys: VerifyKeySource[] = [{ kind: 'symmetric', secret: SECRET, alg: 'HS256' }]
    const augmented = await augmentWithVerification(payload, jwe, keys)
    expect(augmented).toBe(payload)
  })
})

describe('findingsBySeverity', () => {
  it('partitions findings by severity', () => {
    const sample = [
      { id: 'a', severity: 'error', message: 'x' },
      { id: 'b', severity: 'warning', message: 'y' },
      { id: 'c', severity: 'info', message: 'z' },
      { id: 'd', severity: 'error', message: 'w' },
    ] as const
    const bucketed = findingsBySeverity([...sample])
    expect(bucketed.errors).toHaveLength(2)
    expect(bucketed.warnings).toHaveLength(1)
    expect(bucketed.infos).toHaveLength(1)
  })

  it('handles empty input', () => {
    const bucketed = findingsBySeverity([])
    expect(bucketed.errors).toEqual([])
    expect(bucketed.warnings).toEqual([])
    expect(bucketed.infos).toEqual([])
  })
})
