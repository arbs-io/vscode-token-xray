import { describe, expect, it } from 'vitest'
import { samlResponseFixture } from '../analyzers/saml/fixtures'
import { AnalyzerRegistry } from './registry'
import { createDefaultRegistry } from './defaultRegistry'
import {
  DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES,
  scanText,
  shouldDropSecrets,
} from './scanText'

const PEM_KEY = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu',
  'KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm',
  '-----END RSA PRIVATE KEY-----',
].join('\n')

function b64u(json: object): string {
  return Buffer.from(JSON.stringify(json))
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

const ALG_NONE_JWT = `${b64u({ alg: 'none' })}.${b64u({ sub: 'x' })}.`

describe('scanText (positive cases)', () => {
  const reg = createDefaultRegistry()

  it('returns secret findings when settings are not provided (defaults on)', async () => {
    const out = await scanText(PEM_KEY, 'src/leak.ts', reg)
    expect(out.some((d) => d.source === 'secret')).toBe(true)
  })

  it('returns secret findings when secrets.enabled is true', async () => {
    const out = await scanText(PEM_KEY, 'src/leak.ts', reg, { secrets: { enabled: true } })
    expect(out.some((d) => d.code === 'secret.privateKey.pem')).toBe(true)
  })

  it('still emits non-secret findings (JWT alg:none) even with secrets off', async () => {
    const out = await scanText(ALG_NONE_JWT, 'src/index.ts', reg, {
      secrets: { enabled: false },
    })
    expect(out.some((d) => d.source === 'jwt' && d.code === 'jwt.alg.none')).toBe(true)
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })

  it('emits SAML diagnostics regardless of secret settings', async () => {
    const xml = samlResponseFixture({ signed: false })
    const out = await scanText(xml, 'a/b.xml', reg, { secrets: { enabled: false } })
    expect(out.some((d) => d.source === 'saml')).toBe(true)
  })

  it('returns empty for empty input', async () => {
    expect(await scanText('', 'foo.ts', reg)).toEqual([])
  })

  it('returns the empty list when the registry produces no diagnostics', async () => {
    expect(await scanText('plain inert text', 'src/foo.txt', reg)).toEqual([])
  })

  it('falls back to default settings when supplied secrets is undefined', async () => {
    const out = await scanText(PEM_KEY, 'src/leak.ts', reg, {})
    expect(out.some((d) => d.source === 'secret')).toBe(true)
  })

  it('handles a registry with only a non-secret analyzer (no secrets to drop)', async () => {
    const reg2 = new AnalyzerRegistry()
    reg2.register({
      id: 'demo',
      name: 'demo',
      detect: (t) => (t ? [{ text: t, range: { start: 0, end: t.length } }] : []),
      analyze: () => ({
        analyzerId: 'demo',
        kind: 'demo',
        sections: [],
        findings: [{ id: 'demo.x', severity: 'warning' as const, message: 'x' }],
      }),
    })
    const out = await scanText('hello', 'foo.ts', reg2)
    expect(out.some((d) => d.source === 'demo')).toBe(true)
  })
})

describe('scanText (negative — secrets filtering)', () => {
  const reg = createDefaultRegistry()

  it('drops all secret findings when secrets.enabled = false', async () => {
    const out = await scanText(PEM_KEY, 'src/leak.ts', reg, {
      secrets: { enabled: false },
    })
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })

  it('drops secret findings when filename matches a **/*.test.ts exclude', async () => {
    const out = await scanText(PEM_KEY, 'src/foo/leak.test.ts', reg, {
      secrets: { exclude: ['**/*.test.ts'] },
    })
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })

  it('keeps secret findings when the exclude glob does NOT match', async () => {
    const out = await scanText(PEM_KEY, 'src/foo/leak.ts', reg, {
      secrets: { exclude: ['**/*.test.ts'] },
    })
    expect(out.some((d) => d.source === 'secret')).toBe(true)
  })

  it('drops secret findings when filename is under node_modules/**', async () => {
    const out = await scanText(PEM_KEY, 'node_modules/foo/bar.js', reg, {
      secrets: { exclude: ['node_modules/**'] },
    })
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })

  it('keeps secret findings when filename is undefined even if exclude is set', async () => {
    const out = await scanText(PEM_KEY, undefined, reg, {
      secrets: { exclude: ['**/*.test.ts'] },
    })
    expect(out.some((d) => d.source === 'secret')).toBe(true)
  })

  it('drops secret findings when document exceeds maxFileSizeBytes', async () => {
    const big = PEM_KEY + '\n' + 'x'.repeat(2000)
    const out = await scanText(big, 'src/leak.ts', reg, {
      secrets: { maxFileSizeBytes: 100 },
    })
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })

  it('keeps secret findings when document is below maxFileSizeBytes', async () => {
    const out = await scanText(PEM_KEY, 'src/leak.ts', reg, {
      secrets: { maxFileSizeBytes: PEM_KEY.length + 10 },
    })
    expect(out.some((d) => d.source === 'secret')).toBe(true)
  })

  it('keeps non-secret findings even when oversized for secret scanning', async () => {
    const text = ALG_NONE_JWT + '\n' + 'x'.repeat(2000)
    const out = await scanText(text, 'src/leak.ts', reg, {
      secrets: { maxFileSizeBytes: 100 },
    })
    expect(out.some((d) => d.source === 'jwt' && d.code === 'jwt.alg.none')).toBe(true)
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })

  it('respects an exclude entry even with default enabled=true', async () => {
    const out = await scanText(PEM_KEY, 'fixtures/leak.ts', reg, {
      secrets: { enabled: true, exclude: ['fixtures/**'] },
    })
    expect(out.every((d) => d.source !== 'secret')).toBe(true)
  })
})

describe('shouldDropSecrets', () => {
  it('drops when enabled=false', () => {
    expect(shouldDropSecrets('text', 'a.ts', { enabled: false })).toBe(true)
  })

  it('keeps with default settings', () => {
    expect(shouldDropSecrets('text', 'a.ts', undefined)).toBe(false)
    expect(shouldDropSecrets('text', 'a.ts', {})).toBe(false)
  })

  it('drops when text size exceeds maxFileSizeBytes', () => {
    expect(shouldDropSecrets('xxxxxx', 'a.ts', { maxFileSizeBytes: 3 })).toBe(true)
  })

  it('does not drop when text size equals maxFileSizeBytes', () => {
    expect(shouldDropSecrets('xxx', 'a.ts', { maxFileSizeBytes: 3 })).toBe(false)
  })

  it('drops when filename matches an exclude glob', () => {
    expect(shouldDropSecrets('text', 'a/b.test.ts', { exclude: ['**/*.test.ts'] })).toBe(true)
  })

  it('keeps when filename is undefined regardless of exclude', () => {
    expect(shouldDropSecrets('text', undefined, { exclude: ['**'] })).toBe(false)
  })

  it('honours the documented default size limit', () => {
    expect(DEFAULT_SECRETS_MAX_FILE_SIZE_BYTES).toBe(1_048_576)
  })

  it('treats a negative maxFileSizeBytes as disabling the size check', () => {
    const huge = 'x'.repeat(2_000_000)
    expect(shouldDropSecrets(huge, 'a.ts', { maxFileSizeBytes: -1 })).toBe(false)
  })
})
