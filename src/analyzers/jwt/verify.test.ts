import { generateKeyPairSync, randomBytes } from 'crypto'
import { exportJWK, exportSPKI, KeyObject, SignJWT } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { verifyJwt, VerifyKeySource } from './verify'

interface RsKeys {
  privateKey: KeyObject
  publicKey: KeyObject
  spkiPem: string
}

interface EcKeys {
  privateKey: KeyObject
  publicKey: KeyObject
  jwkPublic: Awaited<ReturnType<typeof exportJWK>>
}

const HS_SECRET = 'super-secret-shared-key-1234567890'
let rs: RsKeys
let ec: EcKeys

async function makeJwt(
  alg: string,
  key: Parameters<SignJWT['sign']>[0],
  kid?: string,
  payload: Record<string, unknown> = { sub: 'alice', iss: 'https://example.test' }
): Promise<string> {
  const signer = new SignJWT(payload).setProtectedHeader({ alg, ...(kid ? { kid } : {}) })
  return signer.sign(key)
}

beforeAll(async () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
  rs = {
    privateKey: rsa.privateKey,
    publicKey: rsa.publicKey,
    spkiPem: rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string,
  }
  const ecdsa = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = await exportJWK(ecdsa.publicKey)
  jwk.alg = 'ES256'
  ec = { privateKey: ecdsa.privateKey, publicKey: ecdsa.publicKey, jwkPublic: jwk }
})

describe('verifyJwt — symmetric (HS256)', () => {
  it('verifies a token signed with the matching secret', async () => {
    const secret = new TextEncoder().encode(HS_SECRET)
    const token = await makeJwt('HS256', secret)
    const keys: VerifyKeySource[] = [{ kind: 'symmetric', secret: HS_SECRET, alg: 'HS256' }]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(true)
    expect(result.alg).toBe('HS256')
  })

  it('rejects a token signed with a different secret', async () => {
    const token = await makeJwt('HS256', new TextEncoder().encode(HS_SECRET))
    const keys: VerifyKeySource[] = [
      { kind: 'symmetric', secret: 'other-secret-other-secret-other-secret', alg: 'HS256' },
    ]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(false)
    expect(result.error).toBeDefined()
  })
})

describe('verifyJwt — asymmetric (RS256)', () => {
  it('verifies with a PEM-SPKI public key', async () => {
    const token = await makeJwt('RS256', rs.privateKey)
    const keys: VerifyKeySource[] = [{ kind: 'pem-spki', pem: rs.spkiPem, alg: 'RS256' }]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(true)
    expect(result.alg).toBe('RS256')
  })

  it('rejects with a different RSA keypair', async () => {
    const otherRsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const otherPem = otherRsa.publicKey.export({ type: 'spki', format: 'pem' }) as string
    const token = await makeJwt('RS256', rs.privateKey)
    const keys: VerifyKeySource[] = [{ kind: 'pem-spki', pem: otherPem, alg: 'RS256' }]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(false)
  })
})

describe('verifyJwt — asymmetric (ES256)', () => {
  it('verifies with a JWK public key', async () => {
    const token = await makeJwt('ES256', ec.privateKey)
    const keys: VerifyKeySource[] = [{ kind: 'jwk', jwk: ec.jwkPublic }]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(true)
    expect(result.alg).toBe('ES256')
  })
})

describe('verifyJwt — algorithm mismatch protection', () => {
  it('rejects when token alg != key alg', async () => {
    const token = await makeJwt('HS256', new TextEncoder().encode(HS_SECRET))
    const keys: VerifyKeySource[] = [{ kind: 'pem-spki', pem: rs.spkiPem, alg: 'RS256' }]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/mismatch/i)
  })
})

describe('verifyJwt — kid selection', () => {
  it('uses the key whose kid matches the token header', async () => {
    const token = await makeJwt('RS256', rs.privateKey, 'rs-kid')
    const otherRsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const otherPem = otherRsa.publicKey.export({ type: 'spki', format: 'pem' }) as string
    const keys: VerifyKeySource[] = [
      { kind: 'pem-spki', pem: otherPem, alg: 'RS256', kid: 'wrong-kid' },
      { kind: 'pem-spki', pem: rs.spkiPem, alg: 'RS256', kid: 'rs-kid' },
    ]
    const result = await verifyJwt(token, { keys })
    expect(result.verified).toBe(true)
    expect(result.matchedKeyKid).toBe('rs-kid')
  })
})

describe('verifyJwt — claim assertions', () => {
  it('verifies issuer when supplied', async () => {
    const token = await makeJwt('HS256', new TextEncoder().encode(HS_SECRET))
    const keys: VerifyKeySource[] = [{ kind: 'symmetric', secret: HS_SECRET, alg: 'HS256' }]
    const ok = await verifyJwt(token, { keys, issuer: 'https://example.test' })
    expect(ok.verified).toBe(true)
    const bad = await verifyJwt(token, { keys, issuer: 'https://other.test' })
    expect(bad.verified).toBe(false)
  })
})

describe('verifyJwt — edge cases', () => {
  it('rejects empty token', async () => {
    const r = await verifyJwt('', { keys: [{ kind: 'symmetric', secret: 's', alg: 'HS256' }] })
    expect(r.verified).toBe(false)
    expect(r.error).toMatch(/empty/i)
  })

  it('rejects when no keys configured', async () => {
    const r = await verifyJwt('a.b.c', { keys: [] })
    expect(r.verified).toBe(false)
    expect(r.error).toMatch(/no keys/i)
  })

  it('rejects JWK without alg', async () => {
    const jwk = { ...ec.jwkPublic }
    delete jwk.alg
    const r = await verifyJwt('a.b.c', { keys: [{ kind: 'jwk', jwk }] })
    expect(r.verified).toBe(false)
  })

  it('returns a structured failure when no key matches', async () => {
    const token = await makeJwt('RS256', rs.privateKey, 'real-kid')
    const otherRsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const otherPem = otherRsa.publicKey.export({ type: 'spki', format: 'pem' }) as string
    const keys: VerifyKeySource[] = [
      { kind: 'pem-spki', pem: otherPem, alg: 'RS256', kid: 'other-kid' },
    ]
    const r = await verifyJwt(token, { keys })
    expect(r.verified).toBe(false)
    expect(r.error).toBeDefined()
  })
})

describe('verifyJwt — randomness sanity', () => {
  it('uses a random secret per invocation in negative tests', async () => {
    const token = await makeJwt('HS256', new TextEncoder().encode(HS_SECRET))
    const wrong = randomBytes(32).toString('hex')
    const r = await verifyJwt(token, {
      keys: [{ kind: 'symmetric', secret: wrong, alg: 'HS256' }],
    })
    expect(r.verified).toBe(false)
  })
})
